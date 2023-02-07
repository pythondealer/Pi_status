Pi status is a graphical admin tool for FTP servers, hosted on a headless raspberry pi.

Features:
- check for updates via a graphical user interface
- Restart/ shutdown FTP-Server
-View log files 
- secure key exchange via SCP
- a new session key for each connection

Before you start:
Edit the raspberry IP address and port in server.py
Pi status needs sudo privilege(or at least disable root password for  apt-update and restart/shutdown FTP server) 

Requirements:
Python rsa library
Python Crypto library
Python hashlib library
Python socket library
Python paramiko library
Python getpass library
Python scp library
Python PyQt5 library








