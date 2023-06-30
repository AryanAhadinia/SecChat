import hashlib
import random
import base64
import json
import os
from pathlib import Path
import socket
from _thread import *
from cryptographicio import rsa_
import rsa

from cryptographicio import aes
from cryptographicio import rsa_
from database import key_ring_database

from cryptographicio import aes
from database import user_database
from database import initialize_database
from cryptographicio import hash_lib
from cryptographicio import token
from cryptographicio import nonce_lib

HOST = "127.0.0.1"
UPSTREAM_PORT = 8080
DOWNSTREAM_PORT = 8085

PU, PR = None, None
TOKENS_MAPPING = dict()
USERNAME_SERVER_NONCE_MAPPING = dict()

def encrypt_message(message, self_private_key, destination_public_key):
    signed_message = {
        "message": message,
        "signature": base64.b64encode(rsa_.sign(message, self_private_key)).decode(),
    }
    signed_message_json = json.dumps(signed_message)
    encrypted_message = base64.b64encode(
        rsa_.encrypt(
            signed_message_json,
            destination_public_key,
        )
    ).decode()
    return encrypted_message


def check_sign(message, signature, source_public_key):
    return rsa_.verify(message, signature, source_public_key)


def decrypt_message(encrypted_message, self_private_key):
    signed_message_json = rsa_.decrypt(
        base64.b64decode(encrypted_message),
        self_private_key,
    )
    signed_message = json.loads(signed_message_json)
    return signed_message


def handle_register(message, self_private_key, public_key):
    username = message['username']
    password = message['password']
    salt = f'{random.randint(1_000_000, 9_999_999)}'
    password_hash = hash_lib.calculate_sha256_hash(password + salt)
    if user_database.register_user(username, password_hash, salt):
        key_ring_database.initialize_key(username, public_key)
        response_message = {'status': 'OK', 'success_message': salt}
    else:
        response_message = {'status': 'Error', 'error_message': 'Username already exists'}

    encrypted_message = encrypt_message(json.dumps(response_message), self_private_key, public_key)
    return encrypted_message


def handle_login(message, self_private_key, public_key):
    username = message['username']
    hashed_password = message['hashed_password']
    nonce = message['nonce']

    if user_database.login_user(username, hashed_password):
        new_token = token.generate_token()
        TOKENS_MAPPING[new_token] = username
        print(token)
        server_nonce = nonce_lib.generate_nonce()
        USERNAME_SERVER_NONCE_MAPPING[username] = server_nonce
        response_message = {'status': 'OK', 'token': new_token, 'nonce': nonce,'server_nonce': server_nonce}
    else:
        response_message = {'status': 'Error', 'error_message': 'Invalid username or password'}

    encrypted_message = encrypt_message(json.dumps(response_message), self_private_key, public_key)
    return encrypted_message


def reply_response(connection, self_private_key):
    request_text = ""
    data = connection.recv(1024)
    request_text += data.decode('utf-8')

    decrypted_message = decrypt_message(request_text, self_private_key)
    sign = base64.b64decode(decrypted_message['signature'])
    message = json.loads(decrypted_message['message'])

    if message["procedure"] == "register":
        public_key = rsa.PublicKey.load_pkcs1(base64.b64decode(message['payload']["public_key"]))
        print(public_key)
        if check_sign(decrypted_message['message'], sign, public_key):
            response = handle_register(message['payload'], self_private_key, public_key)
            connection.sendall(response.encode('utf-8'))
        else:
            connection.send("Signature validation failed".encode('utf-8'))

    if message["procedure"] == "login":
        username = message['payload']['username']
        public_key = key_ring_database.get_user_valid_key(username)

        if check_sign(decrypted_message['message'], sign, public_key):
            response = handle_login(message['payload'], self_private_key, public_key)
            connection.sendall(response.encode('utf-8'))
        else:
            connection.send("Signature validation failed".encode('utf-8'))

    if message["procedure"] == "handshake":
        token = message["payload"]["token"]
        try:
            username = TOKENS_MAPPING[token]
            server_nonce = USERNAME_SERVER_NONCE_MAPPING[username]
            public_key = key_ring_database.get_user_valid_key(username)
        except:
            connection.send("".encode('utf-8'))
            return
        
        if check_sign(decrypted_message['message'], sign, public_key):
            response = handle_handshake(message['payload'], self_private_key,server_nonce,public_key)
            connection.sendall(response.encode('utf-8'))
        else:
            connection.send("Signature validation failed".encode('utf-8'))


def handle_handshake(message, self_private_key,server_nonce,public_key):
    nonce = message["nonce"]
    
    if message['server_nonce'] != server_nonce:
        del TOKENS_MAPPING[token]
        response_message = {"status": "Error", "error_message":"Handshake not related to previously logged in user"}
    else:
        session_key = aes.AESCipher._keygen()
        response_message = {"status": "OK", "nonce": nonce, "key": base64.b64encode(session_key).decode()}
    encrypted_message = encrypt_message(json.dumps(response_message), self_private_key, public_key)
    print(nonce)
    return encrypted_message


def main():
    initialize_database.create_tables()
    connection_socket = socket.socket()
    PR = rsa_.load_private_key(Path('server/keys/'))
    PU = rsa_.load_public_key(Path('server/keys/'))
    try:
        connection_socket.bind((HOST, UPSTREAM_PORT))
        print("Socket is listening ...")
        connection_socket.listen(5)
        while True:
            connection, address = connection_socket.accept()
            print("Connected to: " + address[0] + ":" + str(address[1]))
            start_new_thread(reply_response, (connection, PR,))
    except socket.error as e:
        print(str(e))


if __name__ == "__main__":
    main()
