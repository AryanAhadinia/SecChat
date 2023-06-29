import base64
import json
import os
import random
from pathlib import Path
import socket
from cryptographicio import rsa_
from cryptographicio import hash_lib
from database import initialize_database
from database import salt_database

HOST = "127.0.0.1"
UPSTREAM_PORT = 8080
DOWNSTREAM_PORT = 8085


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


def send_receive(message, host, port):
    response = ""
    server_socket = socket.socket()
    server_socket.connect((host, port))
    server_socket.sendall(message.encode('utf-8'))
    data = server_socket.recv(1024)
    print(data)
    response += data.decode()
    server_socket.close()
    return response


def send_request(procedure, payload, self_private_key, destination_public_key):
    http_like_message = {
        "procedure": procedure,
        "payload": payload,
    }
    http_like_message_json = json.dumps(http_like_message)
    encrypted_message = encrypt_message(
        http_like_message_json,
        self_private_key,
        destination_public_key,
    )
    encrypted_response = send_receive(encrypted_message, HOST, UPSTREAM_PORT)
    response = decrypt_message(
        encrypted_response,
        self_private_key,
        destination_public_key,
    )
    return response


def handshake(self_public_key, self_private_key, server_public_key):
    nonce = random.randint(1_000_000_000, 9_999_999_999)
    self_public_key_string = base64.b64encode(self_public_key.save_pkcs1("PEM")).decode()
    response_message = \
        send_request("handshake", {"Nonce": nonce, "PU": self_public_key_string}, self_private_key, server_public_key)[
            "message"]
    nonce_from_server = response_message["Nonce"]
    if nonce != nonce_from_server:
        raise Exception("This message is not Fresh!")
    return response_message["key"]


def handle_register(server_public_key):
    username = input("Username: ")
    password = input("Password: ")
    key_path = Path(f"client/keys/client/{username}")
    if os.path.exists(key_path):
        PU = rsa_.load_public_key(key_path)
        PR = rsa_.load_private_key(key_path, password)
    else:
        os.mkdir(key_path)
        PU, PR = rsa_.generate_keypair()
        rsa_.write_keys(PU, PR, key_path, password)
    print(PU)
    self_public_key_string = base64.b64encode(PU.save_pkcs1("PEM")).decode()
    response = send_request("register",
                            {'username': username, 'password': password, 'public_key': self_public_key_string},
                            PR,
                            server_public_key)
    response = json.loads(response)
    if response['status'] == 'OK':
        salt = response['success_message']

        database_path = Path(f"client/database/databases/{username}")
        if not os.path.exists(database_path):
            os.mkdir(database_path)

        initialize_database.create_tables(database_path, f'{username}.db')
        salt_database.store_salt(salt, database_path, f'{username}.db')

        print('Successfully registered')

    else:
        print(response['error_message'])


def handle_login(server_public_key):
    global PR
    username = input("Username: ")
    password = input("Password: ")
    if not os.path.exists(os.path.join(Path(f"client/database/databases/{username}"), f'{username}.db')):
        print("local database does not exists. please register first")
        return

    salt, = salt_database.get_salt(Path(f"client/database/databases/{username}"), f'{username}.db')
    print(salt)
    hashed_password = hash_lib.calculate_sha256_hash(password + salt)

    key_path = Path(f"client/keys/client/{username}")
    if os.path.exists(key_path):
        PR = rsa_.load_private_key(key_path, password)

    response = send_request("login", {'username': username, 'hashed_password': hashed_password}, PR,
                            server_public_key)

    response = json.loads(response)
    if response['status'] == 'OK':
        token = response['token']
        print('Successfully logged in')

    else:
        print(response['error_message'])


def main():
    global SERVER_PU, PU, PR
    SERVER_PU = rsa_.load_public_key(Path("client/keys/server"))

    while True:
        command = input()
        if command == 'register':
            handle_register(SERVER_PU)
        elif command == 'login':
            handle_login(SERVER_PU)


if __name__ == "__main__":
    main()
