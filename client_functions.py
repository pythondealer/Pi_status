import socket
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Cipher import AES
import base64
import rsa
import hashlib
import paramiko
from scp import SCPClient
import subprocess
import os
import getpass


#AES_VARIABLEN
BS = 16
pad = lambda s: bytes(s + (BS - len(s) % BS) * chr(BS - len(s) % BS), 'utf-8')
unpad = lambda s : s[0:-ord(s[-1:])]




def generate_rsa_key():
    (publicKey, privateKey) = rsa.newkeys(1024)

    with open('privateKey.pem', 'wb') as p:
        p.write(privateKey.save_pkcs1('PEM'))

    with open('publicKey_cli.pem', 'wb') as p:
        p.write(publicKey.save_pkcs1('PEM'))

def generate_session_key():
    session_key = Random.get_random_bytes(32)
    session_key_str = (str(session_key))

    return session_key_str

def key_exchange(password, host, username):
    cwd = os.getcwd()
 
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password)
    ssh = client
    scp = SCPClient(ssh.get_transport())

    os.chdir(cwd)

    scp.get("publicKey_server.pem")
    scp.put("publicKey_cli.pem")
    print("Keyexchange erfolgreich")


def load_pubKey():
    with open('publicKey_cli.pem', 'rb') as p:
        pubKey = rsa.PublicKey.load_pkcs1(p.read())
        return pubKey  

def load_privKey():
    with open('privateKey.pem', 'rb') as p:
        privateKey = rsa.PrivateKey.load_pkcs1(p.read())
        return privateKey    

def load_sever_key(pubKey_server):
    with open('publicKey_server.pem', 'rb') as p:
        pubKey_server = rsa.PublicKey.load_pkcs1(p.read())
        return pubKey_server    

def send_pub_key():
    with open('publicKey.pem', 'rb') as p:
        keydata = p.read()
        s.sendall(keydata)

def encrypt_rsa(cmd ,pubkey):
    enc = rsa.encrypt(cmd, pubkey)
      
    return enc 

def decrypt_session_key(ciphertext, key):
    decrypted = rsa.decrypt(ciphertext, key)

    return decrypted        


def sign(message, key):
    return rsa.sign(message.encode('ascii'), key, 'MD5')


def verify(message, signature, key):
    return rsa.verify(message.encode('ascii'), signature, key,) == 'MD5'


def extract_signature(inp):

    ls = inp.split(b"++*++")
    signature = ls[-1]
    return signature

def encrypt_sign(data_in, AES_key, priv_key):
    data_encrypt = encrypt_AES(data_in, AES_key)

    signature = rsa.sign(data_in.encode('ascii'), priv_key, 'MD5')


    data_out =  (data_encrypt + (b"++*++") + signature)

    return data_out

def recvall(sock):
    BUFF_SIZE = 4096
    data = bytearray()
    while True:
        packet = sock.recv(BUFF_SIZE)
        if not packet:  # Important!!
            break
        data.extend(packet)
    return data


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

if __name__ == "__main__":
    print("HIER SIND NUR FUNKTIONEN DEFINIERT")

