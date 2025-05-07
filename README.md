# SSH Honeypot in Python
An SSH honeypot written in Python using Paramiko. This project logs all unauthorized SSH connection attempts as well as monitors intrusion activity.

# ⚙️ Features

Emulates an SSH server.

Logs all connection attempts and command entries.

Stores logs in a local file (honeypot.log).

Easy to configure and deploy.

# 🛠 Setup

## 1. Clone the Repository
   
git clone https://github.com/yourusername/ssh-honeypot.git

cd ssh-honeypot

## 2. Install Dependencies
   
Make sure you have Python 3 installed. Then install Paramiko:

pip install paramiko

## 3. Generate Server Host Key

This honeypot uses a private key to simulate an SSH server. Generate one using ssh-keygen:

ssh-keygen -f server.key -N ''

This creates a private key file named server.key in the current directory with no passphrase.

## 4. Run the Honeypot
   
python honeypot.py

Once running, the honeypot will listen for incoming SSH connections (I set this to port 2222 for testing purposes) and log all interaction attempts to honeypot.log.

# 📄 Log Output

Each log entry contains:

Timestamp

IP address of the connecting client

Attempted username

Attempted password

### It should look something like this running from a local host:

get_allowed_auths called from IP: 127.0.0.1 | Username: alice

check_auth_password called from IP: 127.0.0.1 | Username: alice | Password: testing

check_channel_request has been called from (127.0.0.1): 0

Attacker from 127.0.0.1 entered: whoami

Attacker from 127.0.0.1 entered: ls

