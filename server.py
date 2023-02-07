import socket
import subprocess
import os
#from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto import Random
import base64
import hashlib
import rsa

#AES_VARIABLES
BS = 16
pad = lambda s: bytes(s + (BS - len(s) % BS) * chr(BS - len(s) % BS), 'utf-8')
unpad = lambda s : s[0:-ord(s[-1:])]    


def generate_key():
    (publicKey, privateKey) = rsa.newkeys(1024)



    with open('privateKey.pem', 'wb') as p:
        p.write(privateKey.save_pkcs1('PEM'))

    with open('publicKey_server.pem', 'wb') as p:
        p.write(publicKey.save_pkcs1('PEM'))


def load_pubKey():
    with open('publicKey_server.pem', 'rb') as p:
        pubKey = rsa.PublicKey.load_pkcs1(p.read())
        return pubKey  

def load_privKey():
    with open('privateKey.pem', 'rb') as p:
        privateKey = rsa.PrivateKey.load_pkcs1(p.read())
        return privateKey  


def load_cli_key(pubKey_cli):
    os.chdir("/home/pi/")

    with open('publicKey_cli.pem', 'rb') as p:
        pubKey_cli = rsa.PublicKey.load_pkcs1(p.read())

    return pubKey_cli



def encrypt(message, key):

    crypted = rsa.encrypt(message, key)

    return crypted


def decrypt(ciphertext, key):

    decrypted = rsa.decrypt(ciphertext, key)
    return decrypted

def sign(message, key):
    return rsa.sign(message.encode('ascii'), key, 'MD5')


def verify(message, signature, key):
    return rsa.verify(message.encode('ascii'), signature, key,) == 'MD5'

def encrypt_sign(data_in, AES_key, priv_key):
    data_encrypt = encrypt_AES(data_in, AES_key)

    signature = rsa.sign(data_in.encode('ascii'), priv_key, 'MD5')


    data_out =  (data_encrypt + (b"++*++") + signature)

    print(len(data_out))
    return data_out


def decrypt_verify(data_in, AES_key, pubKey_cli):
    ls = []
    signature = ("")
    data_encrypt = ("")
    message = ("")

    ls = data_in.split(b"++*++")
    data_encrypt = ls[0]

    data_decrypt = decrypt_AES(data_encrypt, AES_key)

 
    signature = ls[-1]


    message = data_decrypt.decode()
    auth_bool = rsa.verify(message.encode('ascii'), signature, pubKey_cli,) == 'MD5'
    return auth_bool, message

def encrypt_AES(plain_text, key):
    private_key = hashlib.sha256(key.encode("utf-8")).digest()
    plain_text = pad(plain_text)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(plain_text))


def decrypt_AES(cipher_text, key):
    private_key = hashlib.sha256(key.encode("utf-8")).digest()
    cipher_text = base64.b64decode(cipher_text)
    iv = cipher_text[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(cipher_text[16:]))


def send_data(data):
    conn.sendall(data)

    conn.close()

def get_log():
    os.chdir("/var/log")

    f = ("")

    f = open("auth.log", "rt")
    log = f.read()
    f.close()

    print(len(log))
    return log

def get_updates():
    f = open("udate.txt", "wt")
    cmd_exe = subprocess.call(["sudo", "apt", "update"], stdout=f, text=True)
    f.close()
    
    f = open("udate.txt", "r+")
    updates = f.read()
    f.close()

    print(type(updates))
    return updates

def restart_ftp_server():
    cmd_exe = subprocess.call(["sudo", "service", "vsftpd", "restart"])  
    return ("FTP-Server wurde neu gestartet")  

def stop_ftp_server():
    cmd_exe = subprocess.call(["sudo", "service", "vsftpd", "stop"])        
    return ("FTP-Server wurde gestopt")  


HOST = "" #Enter IP adress
PORT = (int()) #Enter PORT
session_key_status = False


privKey = ("")
pubKey = None
pubKey_cli = (b"")


while True:

    generate_key()
    privKey = load_privKey()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()

        while True:

            session_key_status = False  

            print("listening...")
            conn, addr = s.accept()

            with conn:
                print(f"Connected by {addr}")

                while session_key_status == False:
                    session_key = conn.recv(1024) 

                    session_key = decrypt(session_key, privKey)
                    session_key = session_key.decode()
                
                    session_key_info = ("Key exchange successful")                    
                    msg = encrypt_sign(session_key_info, session_key, privKey)
                    conn.sendall(msg)
            
                    session_key_status = True
                    print(" Key exchange successful")

 
                while True:
                    pubKey_cli = load_cli_key(pubKey_cli)

                    cmd_recv = conn.recv(1024)
                    check, cmd = decrypt_verify(cmd_recv, session_key, pubKey_cli)
                       
                    if check and cmd == ("log"):
                        log = get_log()
                        enc_log = encrypt_sign(log, session_key, privKey)
                        conn.sendall(enc_log)
                                                                   
                        break

                    if check and cmd == ("update"):
                        updates = get_updates()
                        enc_updates = encrypt_sign(updates, session_key, privKey)
                        conn.sendall(enc_updates)                                              

                        break


                    if check and cmd == ("restart"):
                        response = restart_ftp_server()                                              
                        enc_response = encrypt_sign(response, session_key, privKey)
                        conn.sendall(enc_response)                                              
                        break

                    if check and cmd == ("stop"):
                        response = stop_ftp_server() 
                        enc_response = encrypt_sign(response, session_key, privKey)
                        conn.sendall(enc_response)                                             
                        break



















