import base64
import json
import os
import random
from pathlib import Path
import socket

from client.cryptographicio import symmetric_ratchet
from client.proto import proto
from cryptographicio import rsa_
from cryptographicio import hash_lib
from cryptographicio import nonce_lib
from database import initialize_database
from database import salt_database
from database import message_database
from cryptographicio import nonce_lib
from _thread import *
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptographicio.first_person_ratchet import FirstPerson

HOST = "127.0.0.1"
UPSTREAM_PORT = 8080
DOWNSTREAM_PORT = 8085
TOKEN = None
SESSION_KEY = None
SERVER_CONNECTION = None
CURRENT_USERNAME = None


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
    global SERVER_CONNECTION
    response = ""
    server_socket = socket.socket()
    server_socket.connect((host, port))
    server_socket.sendall(message.encode('utf-8'))
    data = server_socket.recv(1024)
    print(data)
    response += data.decode()
    SERVER_CONNECTION = server_socket
    return response


def send_request(procedure, payload, self_private_key, destination_public_key, close_connection):
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


def listen_to_server(connection):
    while True:
        input_data = ''
        data = connection.recv(1024)
        input_data += data.decode('utf-8')


def handshake(self_private_key, server_public_key, server_nonce):
    global SESSION_KEY, SERVER_CONNECTION
    nonce = nonce_lib.generate_nonce()
    response_message = \
        send_request("handshake", {"nonce": nonce, "token": TOKEN, "server_nonce": server_nonce}, self_private_key,
                     server_public_key, False)
    response_message = json.loads(response_message)
    if response_message["status"] == 'OK':
        nonce_from_server = response_message["nonce"]
        if nonce != nonce_from_server:
            print("This message is not fresh")
        else:
            SESSION_KEY = base64.b64decode(response_message["key"])
            start_new_thread(listen_to_server, (SERVER_CONNECTION,))
    else:
        print(response_message['error_message'])


def handle_register(server_public_key):
    username = input("Username: ")
    password = input("Password: ")
    key_path = Path(f"client/keys/client/{username}")
    if os.path.exists(key_path):
        print("username already exists")
        return
    else:
        os.mkdir(key_path)
        PU, PR = rsa_.generate_keypair()
        rsa_.write_keys(PU, PR, key_path, password)
    print(PU)
    self_public_key_string = base64.b64encode(PU.save_pkcs1("PEM")).decode()
    response = send_request("register",
                            {'username': username, 'password': password, 'public_key': self_public_key_string},
                            PR,
                            server_public_key, True)
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
    global PR, TOKEN, SESSION_KEY, PU, CURRENT_USERNAME
    username = input("Username: ")
    password = input("Password: ")
    if not os.path.exists(os.path.join(Path(f"client/database/databases/{username}"), f'{username}.db')):
        print("local database does not exists. please register first")
        return

    salt, = salt_database.get_salt(Path(f"client/database/databases/{username}"), f'{username}.db')
    hashed_password = hash_lib.calculate_sha256_hash(password + salt)
    nonce = nonce_lib.generate_nonce()

    key_path = Path(f"client/keys/client/{username}")
    if os.path.exists(key_path):
        try:
            PR = rsa_.load_private_key(key_path, password)
            PU = rsa_.load_public_key(key_path)
        except UnicodeDecodeError:
            print("invalid password")
            return

    response = send_request("login", {'username': username, 'hashed_password': hashed_password,
                                      'nonce': nonce}, PR,
                            server_public_key, True)

    response = json.loads(response)
    if response['status'] == 'OK':
        if response['nonce'] == nonce:
            print(response)
            TOKEN = response['token']
            CURRENT_USERNAME = username
            print(TOKEN)
            print('Successfully logged in')
            return response['server_nonce']
        else:
            print("An old message was received in response of login request")

    else:
        print(response['error_message'])


def handle_chats():
    if CURRENT_USERNAME is None:
        print("login first to view your messages")
        return

    database_path = Path(f"client/database/databases/{CURRENT_USERNAME}")
    database_name = f"{CURRENT_USERNAME}.db"

    if not os.path.exists(os.path.join(database_path, database_name)):
        print("you have no messages in this device")

    results = message_database.get_messages(database_path, database_name, CURRENT_USERNAME)

    for result in results:
        print(f"from {result[1]} to {result[2]}:")
        print(result[3])


def handle_send():
    global TOKEN, SESSION_KEY, PR, SERVER_PU

    if SESSION_KEY is None or TOKEN is None:
        print("please login first")
        return

    dst_user = input("Dest Username: ")
    message = input(">>")

    initial_key = X25519PrivateKey.generate()
    encrypted_message = proto.proto_encrypt(
        json.dumps({"procedure": "diffie_handshake", "dst_user": dst_user, "diffie_key": initial_key.public_key()}),
        TOKEN,
        SESSION_KEY,
        PR, SERVER_PU)
    encrypted_response = send_receive(encrypted_message, HOST, UPSTREAM_PORT)
    response_message, = proto.proto_decrypt(encrypted_response, SESSION_KEY, PR, SERVER_PU)
    other_diffie_public_key = response_message['diffie_key']
    shared_key = symmetric_ratchet.hkdf_(initial_key.exchange(other_diffie_public_key), 32)

    first_person_ratchet = FirstPerson(shared_key)
    first_person_ratchet.dh_ratchet_send(other_diffie_public_key)
    cipher = first_person_ratchet.send(message)
    encrypted_message = proto.proto_encrypt(
        json.dumps({"procedure": "message", "dst_user": dst_user, "cipher": cipher}), TOKEN, SESSION_KEY,
        PR,
        SERVER_PU)
    encrypted_response = send_receive(encrypted_message, HOST, UPSTREAM_PORT)
    response_message, = proto.proto_decrypt(encrypted_response, SESSION_KEY, PR, SERVER_PU)
    if response_message['status'] == "OK":
        print("message successfully sent")
    else:
        print(response_message["error_message"])

    def main():
        global SERVER_PU, PU, PR
        SERVER_PU = rsa_.load_public_key(Path("client/keys/server"))

        while True:
            command = input()
            if command == 'register':
                handle_register(SERVER_PU)
            elif command == 'login':
                server_nonce = handle_login(SERVER_PU)
                if server_nonce is not None:
                    handshake(PR, SERVER_PU, server_nonce)
            elif command == 'chats':
                handle_chats()
            elif command == 'send':
                handle_send()

    if __name__ == "__main__":
        main()
