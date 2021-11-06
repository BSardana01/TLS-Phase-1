import random
import datetime
from Crypto.Util.number import *
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
from base64 import b64encode, b64decode
def generate_CR():
    now = datetime.datetime.now()
    formatted_time = now.strftime('%H:%M:%S, %d:%m:%y')

    client_random = random.randint(1, 999999)
    client_random = str(client_random)
    client_random += ";"
    client_random += formatted_time

    return client_random

def generate_key_pair():  
    randomNumber = Random.new().read
    keys = RSA.generate(1024, randomNumber)
    file = open('private.pem', 'wb')
    file.write(keys.exportKey('PEM'))
    file.close()

    file = open('public.pem', 'wb')
    file.write(keys.publickey().exportKey('PEM'))
    file.close()

def sign_with_key(message, key):
    encryptor = PKCS1_OAEP.new(key)
    encrypted_msg = encryptor.encrypt(str(message).encode())
    encoded_encrypted_msg = b64encode(encrypted_msg)

    return encoded_encrypted_msg

def decrypt_rsa(message, key):
    encryptor = PKCS1_OAEP.new(key)
    decoded_encrypted_msg = b64decode(message)
    decoded_decrypted_msg = encryptor.decrypt(decoded_encrypted_msg)

    return decoded_decrypted_msg

def generate_master_secret(preMaster, client_random, server_random):
    client_random = int(client_random.split(';')[0])
    server_random = int(server_random.split(';')[0])
    preMaster = int(preMaster)

    masterSecret = pow(preMaster, server_random, client_random)
    masterSecret = masterSecret.to_bytes(16, byteorder='big')
    return masterSecret
