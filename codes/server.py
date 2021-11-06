import socket
import os.path
from Crypto import Random
from Crypto.Util.number import *
import json
from Crypto.PublicKey import RSA
from base64 import b64encode


from utilities import generate_CR, generate_key_pair, decrypt_rsa, generate_master_secret
# setting up socket
server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
LOCALHOST = '127.0.0.1'
PORT = 9999

server_socket.bind((LOCALHOST, PORT))
server_socket.listen(5)

print("[*] Starting server...")
server_socket,addr=server_socket.accept()

def main():
    while True:
        # Get request from client
        msg_received = server_socket.recv(4096)
        msg_received = msg_received.decode()

        if msg_received == "exit":
            print("\n[*] Exiting...")
            server_socket.close()
            exit()

        b64 = json.loads(msg_received)
        cipher_suite = b64['cipher_suite']
        client_random = b64['client_random']
        session_id = b64['session_id']

        # selected cipher_suite: TLS_DHE_RSA_WITH_DES_CBC_SHA
        selected_cipher_suite = 'TLS_DHE_RSA_WITH_DES_CBC_SHA'
        isPresent = False

        for i in cipher_suite:
            if i == selected_cipher_suite:
                isPresent = True

        if isPresent == False:
            # send "refuse connection" to client
            print("\n[*] Cipher suite not supported by client, exiting")
            server_socket.send("Connection Refused".encode())
            server_socket.close()
            exit()

        # send server hello to client
        server_random = generate_CR()
        session_id = Random.get_random_bytes(16)
        session_id = b64encode(session_id).decode('utf-8')

        # check if key pair exists
        public_key = ''
        private_key = ''
        if os.path.isfile('public.pem') == True:
            print("\n[*] Key pair already present")
        else:
            print("\n[*] Generating key pair...")
            # generate key pair
            generate_key_pair()

        # reading keys from file
        private = open('private.pem', 'rb').read()
        public = open('public.pem', 'rb').read()

        private_key = RSA.importKey(private)
        public_key = RSA.importKey(public)

        # setting up DH key exchange
        # x is server's part of DH
        # g = 3
        # n = 7
        g = getPrime(256)
        n = getPrime(256)
        # x = 2
        x = getPrime(128)
        # server's part of key exchange
        X = pow(g, x, n)
        message_to_client = json.dumps({
            'selected_cipher_suite': selected_cipher_suite,
            'server_random': server_random,
            'session_id': session_id,
            # server's public key would be published 
            # instead of sharing it here
            'public_key': public.decode(),
            'g': g,
            'n': n,
            'X': X,
        })
        server_socket.send(message_to_client.encode())

        # get Y from client
        # preMaster secret for server: pow(Y, x, n)
        msg_received = server_socket.recv(4096)
        msg_received = msg_received.decode()
        b64 = json.loads(msg_received)

        Y = b64['Y']
        Y = Y.encode()
        Y = decrypt_rsa(Y, private_key)
        Y = Y.decode()
        Y = int(Y)
        preMaster = pow(Y, x, n)
        print("\n[*] PreMaster secret calculated: ", preMaster)

        # Now calculate master secret from:
        # preMaster secret, client_random, server_random
        masterSecret = generate_master_secret(preMaster, client_random, server_random)
        print("\n[*] Master secret generated: ", masterSecret)
        
if __name__=="__main__":
    main()