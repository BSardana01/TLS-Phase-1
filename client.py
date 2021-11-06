import socket
from Crypto.PublicKey import RSA
import json
from Crypto.Util.number import *

from utilities import generate_CR, sign_with_key, generate_master_secret

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
LOCALHOST = '127.0.0.1'
PORT = 9999

print("[*] Starting client...")
client_socket.connect((LOCALHOST, PORT))

def main():
    while True:
        inp = input("\n[*] Press any key to establish first phase, q to exit: ")
        if inp == 'q':
            print("\n[*] Exiting...")
            client_socket.send("exit".encode())
            client_socket.close()
            exit()
        
        # json messages
        # {client_random, session_id, cipher_suite}
        client_random = generate_CR()
        session_id = ""
        cipher_suite_list = ['TLS_ECDHE-RSA-AES256-GCM-SHA384', 'TLS_ECDHE-RSA-AES256-SHA384', 'TLS_ECDHE-RSA-AES256-SHA', 'TLS_DES-CBC3-SHA', 'TLS_DHE_RSA_WITH_DES_CBC_SHA', 'TLS_DH_anon_WITH_RC4_128_MD5', 'TLS_RSA_WITH_RC4_128_SHA']

        message_to_server = json.dumps({
            'cipher_suite': cipher_suite_list,
            'client_random': client_random,
            'session_id': session_id,
        })
        print(message_to_server)
        client_socket.send(message_to_server.encode())

        # get server hello
        message_received = client_socket.recv(4096)
        message_received = message_received.decode()

        if message_received == "Connection Refused":
            print("\n[*] Connection Refused from server, exiting...")
            client_socket.close()
            exit()

        b64 = json.loads(message_received)
        print(message_received)
        selected_cipher_suite = b64['selected_cipher_suite']
        server_random = b64['server_random']
        session_id = b64['session_id']
        public_key = b64['public_key']
        g = b64['g']
        n = b64['n']
        X = b64['X']
        # y = 5
        y = getPrime(128)
        # client's part of key exchange: pow(g, y, n)
        Y = pow(g, y, n)
        public_key = public_key.encode()
        public_key = RSA.import_key(public_key)
        
        Y = sign_with_key(Y, public_key)
        # request server for DH
        message_to_server = json.dumps({
            'Y': Y.decode()
        })
        client_socket.send(message_to_server.encode())

        # preMaster secret for client: pow(X, y, n)
        preMaster = pow(X, y, n)
        print("\n[*] PreMaster secret calculated: ", preMaster)

        # Now calculate master secret from:
        # preMaster secret, client_random, server_random
        masterSecret = generate_master_secret(preMaster, client_random, server_random)
        print("\n[*] Master secret generated: ", masterSecret)

if __name__=="__main__":
    main()
