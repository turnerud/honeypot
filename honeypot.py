import threading
import paramiko
import logging
from logging.handlers import RotatingFileHandler
# RotatingFileHandler creates a new log file once a file size limit is reached
import socket

SSH_BANNER = "SSH-2.0-OpenSSH_8.6"
host_key = paramiko.RSAKey(filename='server.key') # needed to authenticate the server for the client

# Setting up the logger
# https://realpython.com/python-logging/

log = logging.getLogger('eventlogger') # for all events
log.setLevel(logging.INFO) # info level and above 
file_handler = RotatingFileHandler('honeypot.log', maxBytes=5000, backupCount = 5) # up to 5 logs can be created
log_format = logging.Formatter('%(message)s') #default logging format
file_handler.setFormatter(log_format) 
log.addHandler(file_handler) # directs log records to honeypot.log

# Emulated shell for when the ssh session has started:

def fake_shell(channel, client_ip, username):
    channel.send(f"{username}$ ")
    command = "" # user input
    while True:
        try:
            char = channel.recv(1).decode('utf-8', errors='ignore') # convert the byte to human-readable string
            if not char:
                break
            if char == '\r': # enter key
                channel.send('\r\n')
                command = command.strip()

                if command.startswith("ls"): 
                    response = "passwords.txt users.txt personaldata.txt"
                if command.startswith("pwd"): 
                    response = "/home/administrator"
                if command.startswith("whoami"):
                    response = f"{username}"
                if command.startswith("nmap"):
                    response = " Starting Nmap 7.12 ( https://www.nmap.org ) \r \n Scanning. . ."
                if command.startswith("cat"):
                    response = f"Username: {username} | Password: admin /r/n Username: administrator | Password: 1234"
                if command.startswith("cd"):
                    response = f"{command[3:]}: No such file or directory"
                    # Indexed so 'cd ' doesn't show up in response. command[3:]
                if command.strip() == 'exit':
                    response = "Goodbye!"
                    channel.send(response + '\r\n')
                    break
                if command:
                    log.info(f'Attacker ({username}) from {client_ip} entered: {command}')
                channel.send(response + '\r\n')
                
                channel.send(f'{username}$ ')
                command = ""

            # this is for handling backspaces:
            elif char == '\x7f' or char == '\x08': # hex 
                if command:
                    command = command[:-1] # removes last character
                    channel.send('\b \b') # moves cursor back
            # this is so the shell can process user input. all keyboard characters between ' ' and '~' are user-printable in ASCII
            elif char >= ' ' and char <= '~':
                command += char
                channel.send(char)
            else:
                pass
        #if the channel drops the connection, it will be logged
        except Exception as e:
            log.error(f'Error in processing shell commands with {username} on {client_ip}: {e}')
            break
    channel.close()


# server sockets help listen on a specific IP address from the outside world by accepting incoming connection
# resource for documentation: https://mathspp.com/blog/sockets-for-dummies

def server_socket(address, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # this makes the port reusable for testing; as opposed to
    # having to kill the process everytime I want to retest

    #AF = address family, INET = IPv4 addresses, SOCK_STREAM = TCP connection
    server.bind((address, port)) # tells server to listen to incoming connections to this port
    server.listen(5) # max # of client connections 
    print(f"SSH is listening on port {port}")

    while True:
        # accepts client connection
            client, addr = server.accept() # these will be passed to client_handle
            client_thread = threading.Thread(target=client_handle, args=(client, addr))
            client_thread.start()

        
        
# These are the events that will be passed to the logs 
# Default server implementation: https://docs.paramiko.org/en/stable/api/server.html

class ssh_honeypot(paramiko.ServerInterface):
    client_ip = None
    input_username = None

    def __init__(self, client_ip, input_username=None):
        self.client_ip = client_ip
        self.event = threading.Event() # for keeping track of shell requests
    # all of these functions will be responsible for logging client events via Paramiko

    def check_channel_request(self, kind, chanid): # when client requests to open a new channel
        log.info(f'check_channel_request has been called from ({self.client_ip}): {chanid}')
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED # kind will be 'session', so client will think they are in server

    def get_allowed_auths(self, username): # when client asks which authentication methods are allowed
        log.info(f'get_allowed_auths called from IP: {self.client_ip} | Username: {username}')
        self.input_username = username
        return "password, publickey"  # supposed types of authentication

    def check_auth_publickey(self, username, key): #when user tries to login with a public key as opposed to password       
        log.info(f'check_auth_publickey called from IP: {self.client_ip} | Username {username} | Public Key {key}')
        self.input_username = username
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL
    
    def check_auth_password(self, username, password): #when user tries to login with password
        log.info(f'check_auth_password called from IP: {self.client_ip} | Username: {username} | Password: {password}')
        self.input_username = username
        return paramiko.AUTH_SUCCESSFUL
    
    def check_channel_shell_request(self, channel): # when client wants to use shell
        self.event.set() # this will signal shell request is received
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes): 
        # pty - pseudo-terminal for the fake shell
        return True
    
    def check_channel_exec_request(self, channel, command): #when client wants to execute a command
       command_text = str(command.decode("utf-8")) #convert from byte to string
       log.info(f'Client tried to run from ({self.client_ip}): {channel}: {command}')

# This will handle how the client is authenticated and starts the SSH session

def client_handle(client, addr):
    # paramiko.Transport handles SSH handshake and authentication
    # https://medium.com/featurepreneur/ssh-in-python-using-paramiko-e08fd8a039f7
    client_ip = addr[0]    
    transport = paramiko.Transport(client)
    transport.add_server_key(host_key)
    transport.local_version = SSH_BANNER
    
    
    server = ssh_honeypot(client_ip)
    transport.start_server(server=server)
    print(f'{client_ip} has connected to the server.')
    # successful SSH authentication, now wait for client to open a channel
    channel = transport.accept(timeout=20)
    # if client takes too long or gets disconnected:
    if channel is None:
        print("Channel failed to open.")
        transport.close()
        return
    server.event.wait() # wait for shell request to be received by check_channel_shell_request

    welcome_message = "Welcome to my trap server! \r\n" # for when session has been established
    # After the session has been opened, the welcome message will send

    channel.send(welcome_message)
    fake_shell(channel, client_ip=client_ip, username=server.input_username)
    

  
server_socket('127.0.0.1', 2222)







    




