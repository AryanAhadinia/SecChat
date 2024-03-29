import base64
import json
import os
import random
from pathlib import Path
import socket
import hashlib
import time

from cryptographicio import symmetric_ratchet
from proto import proto
from cryptographicio import rsa_
from cryptographicio import hash_lib
from cryptographicio import nonce_lib
from cryptographicio import key_sec_channel
from database import initialize_database
from database import salt_database
from database import message_database
from cryptographicio import nonce_lib
from _thread import *
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptographicio.first_person_ratchet import FirstPerson
from cryptographicio.second_person_ratchet import SecondPerson
from cryptographicio.hkdf_ import hkdf

HOST = "127.0.0.1"
UPSTREAM_PORT = 8080
DOWNSTREAM_PORT = 8085
TOKEN = None
SESSION_KEY = None
SERVER_CONNECTION = None
CURRENT_USERNAME = None
USERNAME_TO_RATCHET_MAPPING = dict()
PASSWORD_HASH = None


def encrypt_message(message, self_private_key, destination_public_key):
    signed_message = {
        "message": message,
        "signature": base64.b64encode(rsa_.sign(message, self_private_key)).decode(),
        "time": time.time(),
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
    global CHAT_CONNECTION
    response = ""
    server_socket = socket.socket()
    server_socket.connect((host, port))
    server_socket.sendall(message.encode('utf-8'))
    while True:
        data = server_socket.recv(1024)
        if data is None:
            break
        response += data.decode('utf-8')
        if len(data) < 1024:
            break
    return response, server_socket


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
    encrypted_response, _ = send_receive(encrypted_message, HOST, UPSTREAM_PORT)
    response = decrypt_message(
        encrypted_response,
        self_private_key,
        destination_public_key,
    )
    return response


def handle_diffie_handshake(message):
    src_user = message['src_username']
    src_diffie_key = message['diffie_key']
    initial_key = X25519PrivateKey.generate()

    sending_public_key = initial_key.public_key()
    sending_public_key_string = base64.b64encode(
        sending_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()

    encrypted_message = proto.proto_encrypt(
        json.dumps({"procedure": "diffie_handshake",
                    "diffie_key": sending_public_key_string, 'nonce': message['nonce']}),
        TOKEN,
        SESSION_KEY,
        PR, SERVER_PU)

    # convert to X25519 public key
    other_diffie_public_key = X25519PublicKey.from_public_bytes(base64.b64decode(src_diffie_key))
    shared_key = hkdf(initial_key.exchange(other_diffie_public_key), 32)

    print(f"new chat createded with {src_user}" , key_sec_channel.to_emojies(shared_key))

    second_person_ratchet = SecondPerson(shared_key)
    second_person_ratchet.DH_ratchet = initial_key
    USERNAME_TO_RATCHET_MAPPING[src_user] = {'type': 'second', 'person_ratchet': second_person_ratchet,
                                             'public_key': other_diffie_public_key,'shared_key': shared_key, 'seq_num_rcv': 0, 'seq_num_snd': 0}

    return encrypted_message


def handle_message(message):
    src_user = message['src_username']
    person_ratchet = USERNAME_TO_RATCHET_MAPPING[src_user]['person_ratchet']
    src_diffie_key = message['diffie_key']
    other_diffie_public_key = X25519PublicKey.from_public_bytes(base64.b64decode(src_diffie_key))
    USERNAME_TO_RATCHET_MAPPING[src_user]['public_key'] = other_diffie_public_key
    seq_number = message['seq_number']
    if seq_number != USERNAME_TO_RATCHET_MAPPING[src_user]['seq_num_rcv']:
        encrypted_message = proto.proto_encrypt(
        json.dumps({"status": "Failed", "message": "Packet's order are not correct"}),
        TOKEN,
        SESSION_KEY,
        PR, SERVER_PU)
        del USERNAME_TO_RATCHET_MAPPING[src_user]
        return
    USERNAME_TO_RATCHET_MAPPING[src_user]['seq_num_rcv'] = USERNAME_TO_RATCHET_MAPPING[src_user]['seq_num_rcv'] + 1
    person_ratchet.dh_ratchet_recv(other_diffie_public_key)
    cipher = base64.b64decode(message['cipher'])
    msg = person_ratchet.recv(cipher, other_diffie_public_key)
    print(msg)
    encrypted_message = proto.proto_encrypt(
        json.dumps({"status": "OK"}),
        TOKEN,
        SESSION_KEY,
        PR, SERVER_PU)
    return encrypted_message, msg.decode('utf-8')


def listen_to_server(connection, self_private_key, server_public_key):
    while True:
        request_text = ""
        while True:
            data = connection.recv(1024)
            if data is None:
                break
            request_text += data.decode('utf-8')
            if len(data) < 1024:
                break

        message, _, sign = proto.proto_decrypt_get_sign(request_text, SESSION_KEY, self_private_key, server_public_key)
        message = json.loads(message)
        print(message)
        if message['procedure'] == 'diffie handshake':
            response = handle_diffie_handshake(message)
            connection.sendall(response.encode('utf-8'))
        if message['procedure'] == 'message':
            response, decrypted_message = handle_message(message)
            database_path = Path(f"client/database/databases/{CURRENT_USERNAME}")
            database_name = f'{CURRENT_USERNAME}.db'
            message_database.add_message(database_path, database_name, message['src_username'], CURRENT_USERNAME,
                                         decrypted_message, message['group_name'], sign, PASSWORD_HASH)
            connection.sendall(response.encode('utf-8'))
        if message['procedure'] == 'ping':
            pass


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
            encrypted_message = proto.proto_encrypt(json.dumps({"procedure": "add_socket", "token": TOKEN}), TOKEN
                                                    , SESSION_KEY, self_private_key, server_public_key)
            encrypted_response, chat_socket = send_receive(encrypted_message, HOST, DOWNSTREAM_PORT)
            decrypted_message, _ = proto.proto_decrypt(encrypted_response, SESSION_KEY, self_private_key,
                                                       server_public_key)
            decrypted_message = json.loads(decrypted_message)
            if decrypted_message['status'] == 'OK':
                print("Socket successfully added to server")
            else:
                print("adding socket failed")
            start_new_thread(listen_to_server, (chat_socket, self_private_key, server_public_key,))
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
    global PASSWORD_HASH
    PASSWORD_HASH = hashlib.sha256(password.encode()).digest()
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

            TOKEN = response['token']
            CURRENT_USERNAME = username

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

    results = message_database.get_messages(database_path, database_name, CURRENT_USERNAME, PASSWORD_HASH)

    for result in results:
        if result[3] != "":
            print(f"In Group: {result[3]}")

        print(f"from {result[0]} to {result[1]}:")
        print(result[2])


def handle_send():
    global TOKEN, SESSION_KEY, PR, SERVER_PU

    if SESSION_KEY is None or TOKEN is None:
        print("please login first")
        return

    target = input("Target (I/G): ").upper()
    if target.upper() == 'I':
        target_name = input("Dest Username: ")
        dst_users = [target_name]
        group_name = ""
    elif target.upper() == 'G':
        target_name = input("Dest Group: ")
        dst_users = handle_get_group_members(target_name)
        if dst_users is None:
            return
        group_name = target_name
    else:
        print("Invalid character")
        return

    message = input(f"{target_name} << ")
    for dst_user in dst_users:
        if dst_user == CURRENT_USERNAME:
            continue
        if USERNAME_TO_RATCHET_MAPPING.get(dst_user) is None:
            nonce = nonce_lib.generate_nonce()
            initial_key = X25519PrivateKey.generate()
            sending_public_key = initial_key.public_key()
            sending_public_key_string = base64.b64encode(
                sending_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
            encrypted_message = proto.proto_encrypt(
                json.dumps({"procedure": "diffie_handshake", "dst_user": dst_user,
                            "diffie_key": sending_public_key_string, "nonce": nonce}),
                TOKEN,
                SESSION_KEY,
                PR, SERVER_PU)
            encrypted_response, _ = send_receive(encrypted_message, HOST, DOWNSTREAM_PORT)
            response_message, _ = proto.proto_decrypt(encrypted_response, SESSION_KEY, PR, SERVER_PU)
            response_message = json.loads(response_message)
            
            if response_message['status'] == 'Failed':
                print(response_message['message'])
                return
            
            if response_message['nonce'] != nonce:
                print("The key is not fresh")
                return 
            
            other_diffie_public_key = response_message['diffie_key']
            other_diffie_public_key = X25519PublicKey.from_public_bytes(base64.b64decode(other_diffie_public_key))
            shared_key = hkdf(initial_key.exchange(other_diffie_public_key), 32)
            person_ratchet = FirstPerson(shared_key)
            person_ratchet.DHratchet = initial_key
            USERNAME_TO_RATCHET_MAPPING[dst_user] = {'type': 'second', 'person_ratchet': person_ratchet,
                                                     'public_key': other_diffie_public_key, 'seq_num_snd': 0,  'seq_num_rcv': 0}
            print(f"new chat createded with {dst_user}" , key_sec_channel.to_emojies(shared_key))

        else:
            print(USERNAME_TO_RATCHET_MAPPING[dst_user])
            person_ratchet = USERNAME_TO_RATCHET_MAPPING[dst_user]['person_ratchet']
            other_diffie_public_key = USERNAME_TO_RATCHET_MAPPING[dst_user]['public_key']

        new_pub_key = person_ratchet.dh_ratchet_send(other_diffie_public_key)
        new_public_key_string = base64.b64encode(
            new_pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        cipher = person_ratchet.send(message.encode('utf-8'))
        cipher_string = base64.b64encode(cipher).decode()


        print(USERNAME_TO_RATCHET_MAPPING[dst_user])
        encrypted_message = proto.proto_encrypt(
            json.dumps({
                "procedure": "message",
                "dst_user": dst_user,
                "cipher": cipher_string,
                "diffie_key": new_public_key_string,
                "group_name": group_name,
                "target_name": target_name,
                "seq_number": USERNAME_TO_RATCHET_MAPPING[dst_user]['seq_num_snd']
            }),
            TOKEN,
            SESSION_KEY,
            PR,
            SERVER_PU
        )
        encrypted_response, _ = send_receive(encrypted_message, HOST, DOWNSTREAM_PORT)
        response_message, _ = proto.proto_decrypt(encrypted_response, SESSION_KEY, PR, SERVER_PU)
        response_message = json.loads(response_message)
        if response_message['status'] == "OK":
            print("message successfully sent")
            USERNAME_TO_RATCHET_MAPPING[dst_user]['seq_num_snd'] = USERNAME_TO_RATCHET_MAPPING[dst_user]['seq_num_snd']   + 1
        else:
            del USERNAME_TO_RATCHET_MAPPING[dst_user]
            print(response_message["error_message"])


def handle_create_group():
    group_name = input("Group Name: ")
    message = json.dumps({"procedure": "create_group", "group_name": group_name})
    encrypted_message = proto.proto_encrypt(message, TOKEN, SESSION_KEY, PR, SERVER_PU)
    encrypted_response, _ = send_receive(encrypted_message, HOST, DOWNSTREAM_PORT)
    response_message, _ = proto.proto_decrypt(encrypted_response, SESSION_KEY, PR, SERVER_PU)
    response_message = json.loads(response_message)
    if response_message['status'] == "OK":
        print("group successfully created")
    else:
        print(response_message["message"])


def handle_add_user_to_group():
    group_name = input("Group Name: ")
    new_user = input("New User: ")
    message = json.dumps({"procedure": "add_user_to_group", "group_name": group_name, "new_user": new_user})
    encrypted_message = proto.proto_encrypt(message, TOKEN, SESSION_KEY, PR, SERVER_PU)
    encrypted_response, _ = send_receive(encrypted_message, HOST, DOWNSTREAM_PORT)
    response_message, _ = proto.proto_decrypt(encrypted_response, SESSION_KEY, PR, SERVER_PU)
    response_message = json.loads(response_message)
    if response_message['status'] == "OK":
        print("user successfully added to group")
    else:
        print(response_message["message"])


def handle_remove_user_from_group():
    group_name = input("Group Name: ")
    user_to_remove = input("User to remove: ")
    message = json.dumps(
        {"procedure": "remove_user_from_group", "group_name": group_name, "user_to_remove": user_to_remove})
    encrypted_message = proto.proto_encrypt(message, TOKEN, SESSION_KEY, PR, SERVER_PU)
    encrypted_response, _ = send_receive(encrypted_message, HOST, DOWNSTREAM_PORT)
    response_message, _ = proto.proto_decrypt(encrypted_response, SESSION_KEY, PR, SERVER_PU)
    response_message = json.loads(response_message)
    if response_message['status'] == "OK":
        print("user successfully removed from group")
    else:
        print(response_message["message"])


def handle_get_group_members(group_name):
    message = json.dumps({"procedure": "get_group_members", "group_name": group_name})
    encrypted_message = proto.proto_encrypt(message, TOKEN, SESSION_KEY, PR, SERVER_PU)
    encrypted_response, _ = send_receive(encrypted_message, HOST, DOWNSTREAM_PORT)
    response_message, _ = proto.proto_decrypt(encrypted_response, SESSION_KEY, PR, SERVER_PU)
    response_message = json.loads(response_message)
    if response_message['status'] == "OK":
        return response_message['group_members']
    else:
        print(response_message["message"])
        return None


def handle_view_groups():
    message = json.dumps({"procedure": "get_groups_for_user"})
    encrypted_message = proto.proto_encrypt(message, TOKEN, SESSION_KEY, PR, SERVER_PU)
    encrypted_response, _ = send_receive(encrypted_message, HOST, DOWNSTREAM_PORT)
    response_message, _ = proto.proto_decrypt(encrypted_response, SESSION_KEY, PR, SERVER_PU)
    response_message = json.loads(response_message)
    if response_message['status'] == "OK":
        return response_message['groups']
    else:
        print(response_message["error_message"])

def handle_get_online_members():
    message = json.dumps({"procedure": "get_online_users"})
    encrypted_message = proto.proto_encrypt(message, TOKEN, SESSION_KEY, PR, SERVER_PU)
    encrypted_response, _ = send_receive(encrypted_message, HOST, DOWNSTREAM_PORT)
    response_message, _ = proto.proto_decrypt(encrypted_response, SESSION_KEY, PR, SERVER_PU)
    response_message = json.loads(response_message)
    if response_message['status'] == "OK":
        online_users = response_message['online_users']
        for user in online_users:
            print(user)
    else:
        print(response_message["error_message"])


def handle_change_password():
    global PR
    username = CURRENT_USERNAME
    old_password = input("Old Password: ")
    new_password = input("New Password: ")
    message = json.dumps({"procedure": "change_password", "username": username, "old_password": old_password, "new_password": new_password})
    encrypted_message = proto.proto_encrypt(message, TOKEN, SESSION_KEY, PR, SERVER_PU)
    encrypted_response, _ = send_receive(encrypted_message, HOST, DOWNSTREAM_PORT)
    response_message, _ = proto.proto_decrypt(encrypted_response, SESSION_KEY, PR, SERVER_PU)
    response_message = json.loads(response_message)
    

    # decrypt private key and encrypt with new password
    if response_message['status'] == "OK":
        print("password successfully changed")
        global PASSWORD_HASH
        PASSWORD_HASH = hashlib.sha256(new_password.encode()).digest()
        database_path = Path(f"client/database/databases/{CURRENT_USERNAME}")
        database_name = f'{CURRENT_USERNAME}.db'
        message_database.re_encrypt_messages(database_path, database_name, old_password, new_password)
        key_path = Path(f"client/keys/client/{username}")
        PR = rsa_.load_private_key(key_path, old_password)
        PU = rsa_.load_public_key(key_path)
        rsa_.write_keys(PU, PR, key_path, new_password)
    else:
        print(response_message["error_message"])


def handle_change_public_key():
    global PU, PR
    new_pu, new_pr = rsa_.generate_keypair()
    new_pu_to_send = base64.b64encode(new_pu.save_pkcs1("PEM")).decode()
    message = json.dumps({"procedure": "change_public_key", "username": CURRENT_USERNAME, "new_public_key": new_pu_to_send})
    encrypted_message = proto.proto_encrypt(message, TOKEN, SESSION_KEY, PR, SERVER_PU)
    encrypted_response, _ = send_receive(encrypted_message, HOST, DOWNSTREAM_PORT)
    response_message, _ = proto.proto_decrypt(encrypted_response, SESSION_KEY, PR, SERVER_PU)
    response_message = json.loads(response_message)
    if response_message['status'] == "OK":
        print("public key successfully changed")
        PU = new_pu
        PR = new_pr
        rsa_.write_keys(PU, PR, Path(f"client/keys/client/{CURRENT_USERNAME}"), PASSWORD_HASH)
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
        elif command == 'create_group':
            handle_create_group()
        elif command == 'add_user_to_group':
            handle_add_user_to_group()
        elif command == 'remove_user_from_group':
            handle_remove_user_from_group()
        elif command == 'get_group_members':
            handle_get_group_members()
        elif command == 'view_groups':
            handle_view_groups()
        elif command == 'get_online_users':
            handle_get_online_members()
        elif command == 'change_password':
            handle_change_password()
        elif command == 'change_public_key':
            handle_change_public_key()
        else:
            print("invalid command")


if __name__ == "__main__":
    main()
