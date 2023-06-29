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

from database import user_database

from cryptographicio import aes
from database import user_database
HOST = "127.0.0.1"
UPSTREAM_PORT = 8080
DOWNSTREAM_PORT = 8085

PU, PR = None, None


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


def decrypt_message(encrypted_message, self_private_key, destination_public_key):
    signed_message_json = rsa_.decrypt(
        base64.b64decode(encrypted_message),
        self_private_key,
    )
    signed_message = json.loads(signed_message_json)
    message = signed_message["message"]
    signature = base64.b64decode(signed_message["signature"])
    if not rsa_.verify(message, signature, destination_public_key):
        raise Exception("Signature is not valid")
    return message


def calculate_sha256_hash(string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(string.encode('utf-8'))
    hash_result = sha256_hash.hexdigest()
    return hash_result


def handle_register(message, self_private_key):
    username = message['username']
    password = message['password']
    public_key = message['public_key']
    salt = f'{random.randint(1_000_000,9_999_999)}'
    password_hash = calculate_sha256_hash(password + salt)
    if user_database.register_user(username, password_hash, salt):
        response_message = {'status': 'OK', 'error_message':''}
    else:
        response_message =  {'status': 'OK', 'error_message':'Username already exists'}

    encrypted_message = encrypt_message(response_message, self_private_key, public_key)
    return encrypt_message

def reply_response(connection, self_private_key):
    request_text = ""
    while True:
        data = connection.recv(1024)
        if not data:
            break
        request_text += data.decode()
    decrypted_message = decrypt_message(request_text, PR, PU)
    if decrypted_message["procedure"] == "register":
        response = handle_register(decrypted_message["message"])
        connection.sendall(response)
    if decrypted_message["procedure"] == "handshake":
        response = handle_handshake(decrypted_message["message"], self_private_key)
        connection.sendall(response)


def handle_handshake(message, self_private_key):
    nonce = message["Nonce"]
    public_key = rsa.PrivateKey.load_pkcs1(base64.b64decode(message["key"]))
    session_key = aes.generate_key()
    response_message = {"Nonce": nonce, "key": session_key}
    encrypted_message = encrypt_message(response_message, self_private_key, public_key)
    print(nonce)
    return encrypted_message


def main():
    connection_socket = socket.socket()
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
