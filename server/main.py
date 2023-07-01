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

from proto import proto
from database import user_database
from database import initialize_database
from database import group_database
from database import group_member_database
from cryptographicio import hash_lib
from cryptographicio import token
from cryptographicio import nonce_lib

from sqlite3 import IntegrityError

HOST = "127.0.0.1"
UPSTREAM_PORT = 8080
DOWNSTREAM_PORT = 8085

PU, PR = None, None
TOKENS_TO_USERNAME_MAPPING = dict()
USERNAME_TO_SERVER_NONCE_MAPPING = dict()
TOKEN_TO_CONNECTION_MAPPING = dict()
TOKEN_TO_AES_MAPPING = dict()


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
        TOKENS_TO_USERNAME_MAPPING[new_token] = username
        server_nonce = nonce_lib.generate_nonce()
        USERNAME_TO_SERVER_NONCE_MAPPING[username] = server_nonce
        response_message = {'status': 'OK', 'token': new_token, 'nonce': nonce, 'server_nonce': server_nonce}
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
        if check_sign(decrypted_message['message'], sign, public_key):
            response = handle_register(message['payload'], self_private_key, public_key)
            connection.sendall(response.encode('utf-8'))
        else:
            connection.send("Signature validation failed".encode('utf-8'))
        connection.close()

    if message["procedure"] == "login":
        username = message['payload']['username']
        public_key = key_ring_database.get_user_valid_key(username)

        if check_sign(decrypted_message['message'], sign, public_key):
            response = handle_login(message['payload'], self_private_key, public_key)
            connection.sendall(response.encode('utf-8'))
        else:
            connection.send("Signature validation failed".encode('utf-8'))
        connection.close()

    if message["procedure"] == "handshake":
        token = message["payload"]["token"]
        try:
            username = TOKENS_TO_USERNAME_MAPPING[token]
            server_nonce = USERNAME_TO_SERVER_NONCE_MAPPING[username]
            public_key = key_ring_database.get_user_valid_key(username)
        except:
            connection.send("".encode('utf-8'))

            return

        if check_sign(decrypted_message['message'], sign, public_key):
            response = handle_handshake(message['payload'], self_private_key, server_nonce, public_key, connection)
            connection.sendall(response.encode('utf-8'))

        else:
            connection.send("Signature validation failed".encode('utf-8'))
            connection.close()


def handle_handshake(message, self_private_key, server_nonce, public_key, conn):
    global TOKEN_TO_CONNECTION_MAPPING
    nonce = message["nonce"]

    if message['server_nonce'] != server_nonce:
        del TOKENS_TO_USERNAME_MAPPING[token]
        response_message = {"status": "Error", "error_message": "Handshake not related to previously logged in user"}
    else:
        session_key = aes.AESCipher._keygen()
        TOKEN_TO_AES_MAPPING[message['token']] = session_key
        response_message = {"status": "OK", "nonce": nonce, "key": base64.b64encode(session_key).decode()}

    encrypted_message = encrypt_message(json.dumps(response_message), self_private_key, public_key)

    return encrypted_message


def handle_add_socket(connection, session_key, self_private_key, other_public_key, token):
    TOKEN_TO_CONNECTION_MAPPING[token] = connection
    encrypted_message = proto.proto_encrypt(json.dumps({"status": "OK"}), "Server"
                                            , session_key, self_private_key, other_public_key)
    return encrypted_message


def get_sessionkey_from_username(username):
    for key, val in TOKENS_TO_USERNAME_MAPPING.items():
        if val == username:
            return TOKEN_TO_AES_MAPPING[key]


def get_token_from_username(username):
    for key, val in TOKENS_TO_USERNAME_MAPPING.items():
        if val == username:
            return key


def handle_diffie_handshake(message, self_private_key, token):
    dst_username = message['dst_user']
    session_key = get_sessionkey_from_username(dst_username)
    dst_token = get_token_from_username(dst_username)
    connection = TOKEN_TO_CONNECTION_MAPPING[dst_token]
    username = TOKENS_TO_USERNAME_MAPPING[token]
    src_diffie_helman = message['diffie_key']
    other_public_key = key_ring_database.get_user_valid_key(dst_username)
    encrypted_message = proto.proto_encrypt(json.dumps({"procedure": "diffie handshake",
                                                        "diffie_key": src_diffie_helman, "src_username": username}),
                                            "Server"
                                            , session_key, self_private_key, other_public_key)
    connection.sendall(encrypted_message.encode('utf-8'))
    diffie_response = ""
    while True:
        data = connection.recv(1024)
        if data is None:
            break
        diffie_response += data.decode('utf-8')
        if len(data) < 1024:
            break

    source_session_key = TOKEN_TO_AES_MAPPING[token]
    source_public_key = key_ring_database.get_user_valid_key(username)

    decrypted_message = proto.proto_decrypt(diffie_response, session_key, self_private_key, other_public_key)
    loaded_message = json.loads(decrypted_message)
    diffie_key = loaded_message['diffie_key']
    encrypted_response_to_source = proto.proto_encrypt(json.dumps({"diffie_key": diffie_key}), "Server",
                                                       source_session_key, self_private_key,
                                                       source_public_key)
    return encrypted_response_to_source


def handle_get_massage(message, self_private_key, token):
    dst_username = message['dst_user']
    session_key = get_sessionkey_from_username(dst_username)
    dst_token = get_token_from_username(dst_username)
    connection = TOKEN_TO_CONNECTION_MAPPING[dst_token]
    username = TOKENS_TO_USERNAME_MAPPING[token]
    src_diffie_helman = message['diffie_key']
    other_public_key = key_ring_database.get_user_valid_key(dst_username)
    src_public_key = key_ring_database.get_user_valid_key(username)

    group_name = message['group_name']
    try:
        group_id = group_database.get_group_id(group_name)
    except:
        response = proto.proto_encrypt(
            json.dumps({"status": "error", "error_message": "this group is not valid or you are not in it"}),
            # this group is not valid
            token,
            TOKEN_TO_AES_MAPPING[token],
            self_private_key,
            src_public_key)
        return response

    members = group_member_database.get_group_members(group_id)
    if username not in members:
        response = proto.proto_encrypt(
            json.dumps({"status": "error", "error_message": "this group is not valid or you are not in it"}),
            # you are not in this group
            token,
            TOKEN_TO_AES_MAPPING[token],
            self_private_key,
            src_public_key)
        return response

    encrypted_message = proto.proto_encrypt(json.dumps(
        {"procedure": "message",
         "diffie_key": src_diffie_helman,
         "cipher": message['cipher'],
         "src_username": username,
         "group_name": group_name}),
        "Server"
        , session_key, self_private_key, other_public_key)
    connection.sendall(encrypted_message.encode('utf-8'))
    diffie_response = ""
    while True:
        data = connection.recv(1024)
        if data is None:
            break
        diffie_response += data.decode('utf-8')
        if len(data) < 1024:
            break

    source_session_key = TOKEN_TO_AES_MAPPING[token]
    source_public_key = key_ring_database.get_user_valid_key(username)

    decrypted_message = proto.proto_decrypt(diffie_response, session_key, self_private_key, other_public_key)
    loaded_message = json.loads(decrypted_message)
    encrypted_response_to_source = proto.proto_encrypt(json.dumps({"status": loaded_message['status']}), "Server",
                                                       source_session_key, self_private_key,
                                                       source_public_key)
    return encrypted_response_to_source


def handle_create_group(message, username, session_key, self_private_key, other_public_key):
    group_name = message['group_name']
    group_admin = username
    try:
        group_database.add_group(group_name, group_admin)
    except IntegrityError:
        encrypted_message = proto.proto_encrypt(json.dumps({"status": "Failed", "message": "Already exists"}), "Server",
                                                session_key, self_private_key, other_public_key)
        return encrypted_message
    group_member_database.add_user_to_group(group_database.get_group_id(group_name), group_admin)
    encrypted_message = proto.proto_encrypt(json.dumps({"status": "OK"}), "Server", session_key, self_private_key,
                                            other_public_key)
    return encrypted_message


def handle_add_user_to_group(message, username, session_key, self_private_key, other_public_key):
    group_name = message['group_name']
    new_user = message['new_user']
    try:
        group_id = group_database.get_group_id(group_name)
    except:
        encrypted_message = proto.proto_encrypt(json.dumps({
            "status": "Failed", "message":"group does not exist"}),
            "Server", session_key, self_private_key, other_public_key)
        print(encrypted_message)
        return encrypted_message
    group_admin = group_database.get_group_admin(group_id)
    if group_admin != username:
        encrypted_message = proto.proto_encrypt(json.dumps(
            {"status": "Failed", "message": "You are not admin"}),
            "Server", session_key,
            self_private_key,
            other_public_key)
        return encrypted_message
    try:
        
        group_member_database.add_user_to_group(group_id, new_user)
    except:
        encrypted_message = proto.proto_encrypt(
            json.dumps({"status": "Failed", "message": "Operation failed. Already in"}), "Server", session_key,
            self_private_key, other_public_key)
        return encrypted_message
    encrypted_message = proto.proto_encrypt(json.dumps({"status": "OK"}), "Server", session_key, self_private_key,
                                            other_public_key)
    return encrypted_message


def handle_remove_user_from_group(message, username, session_key, self_private_key, other_public_key):
    group_name = message['group_name']
    user_to_remove = message['user_to_remove']
    group_id = group_database.get_group_id(group_name)
    group_admin = group_database.get_group_admin(group_id)
    if group_admin != username:
        encrypted_message = proto.proto_encrypt(json.dumps({"status": "You are not admin"}), "Server", session_key,
                                                self_private_key, other_public_key)
        return encrypted_message
    group_member_database.remove_user_from_group(group_id, user_to_remove)
    encrypted_message = proto.proto_encrypt(json.dumps({"status": "OK"}), "Server", session_key, self_private_key,
                                            other_public_key)
    return encrypted_message


def handle_get_group_members(message, username, session_key, self_private_key, other_public_key):
    group_name = message['group_name']
    group_id = group_database.get_group_id(group_name)
    group_members = group_member_database.get_group_members(group_id)
    if username not in group_members:
        encrypted_message = proto.proto_encrypt(json.dumps({"status": "You are not in this group"}), "Server",
                                                session_key, self_private_key, other_public_key)
        return encrypted_message
    encrypted_message = proto.proto_encrypt(json.dumps({"status": "OK", "group_members": group_members}), "Server",
                                            session_key, self_private_key, other_public_key)
    return encrypted_message


def handle_get_groups_for_user(message, username, session_key, self_private_key, other_public_key):
    groups = group_member_database.get_groups_for_user(username)
    encrypted_message = proto.proto_encrypt(json.dumps({"status": "OK", "groups": groups}), "Server", session_key,
                                            self_private_key, other_public_key)
    return encrypted_message


def handle_get_online_users(message, username, session_key, self_private_key, other_public_key):
    live_socket_tokens = set()
    for token, connection in TOKEN_TO_CONNECTION_MAPPING.items():
        live_socket_tokens.add(token)
    live_users = list()
    for token in live_socket_tokens:
        live_users.append(TOKENS_TO_USERNAME_MAPPING[token])
    encrypted_message = proto.proto_encrypt(json.dumps({"status": "OK", "online_users": live_users}), "Server",
                                            session_key, self_private_key, other_public_key)
    return encrypted_message


def reply_chat(connection, PR):
    request_text = ""
    while True:
        data = connection.recv(1024)
        if data is None:
            break
        request_text += data.decode('utf-8')
        if len(data) < 1024:
            break
    token = proto.proto_get_token(request_text, PR)
    username = TOKENS_TO_USERNAME_MAPPING[token]
    public_key = key_ring_database.get_user_valid_key(username)
    session_key = TOKEN_TO_AES_MAPPING[token]

    message = proto.proto_decrypt(request_text, session_key, PR, public_key)
    message = json.loads(message)
    if message['procedure'] == 'diffie_handshake':
        response = handle_diffie_handshake(message, PR, token)
        connection.sendall(response.encode('utf-8'))
    if message['procedure'] == 'message':
        response = handle_get_massage(message, PR, token)
        connection.sendall(response.encode('utf-8'))
    if message['procedure'] == 'add_socket':
        response = handle_add_socket(connection, session_key, PR, public_key, token)
        connection.sendall(response.encode('utf-8'))

    if message['procedure'] == 'create_group':
        response = handle_create_group(message, username, session_key, PR, public_key)
        connection.sendall(response.encode('utf-8'))
    if message['procedure'] == 'add_user_to_group':
        response = handle_add_user_to_group(message, username, session_key, PR, public_key)
        connection.sendall(response.encode('utf-8'))
    if message['procedure'] == 'get_group_members':
        response = handle_get_group_members(message, username, session_key, PR, public_key)
        connection.sendall(response.encode('utf-8'))
    if message['procedure'] == 'remove_user_from_group':
        response = handle_remove_user_from_group(message, username, session_key, PR, public_key)
        connection.sendall(response.encode('utf-8'))
    if message['procedure'] == 'get_groups_for_user':
        response = handle_get_groups_for_user(message, username, session_key, PR, public_key)
        connection.sendall(response.encode('utf-8'))
    if message['procedure'] == 'get_online_users':
        response = handle_get_online_users(message, username, session_key, PR, public_key)
        connection.sendall(response.encode('utf-8'))


def new_protocol(PU, PR):
    try:
        connection_socket = socket.socket()
        connection_socket.bind((HOST, DOWNSTREAM_PORT))
        print("Socket chat is listening ...")
        connection_socket.listen(5)
        while True:
            connection, address = connection_socket.accept()
            print("Connected to: " + address[0] + ":" + str(address[1]))
            start_new_thread(reply_chat, (connection, PR,))
    except socket.error as e:
        print(str(e))


def main():
    initialize_database.create_tables()
    connection_socket = socket.socket()
    PR = rsa_.load_private_key(Path('server/keys/'))
    PU = rsa_.load_public_key(Path('server/keys/'))
    try:
        connection_socket.bind((HOST, UPSTREAM_PORT))
        print("Socket is listening ...")
        start_new_thread(new_protocol, (PU, PR,))
        connection_socket.listen(5)
        while True:
            connection, address = connection_socket.accept()
            print("Connected to: " + address[0] + ":" + str(address[1]))
            start_new_thread(reply_response, (connection, PR,))
    except socket.error as e:
        print(str(e))


if __name__ == "__main__":
    main()
