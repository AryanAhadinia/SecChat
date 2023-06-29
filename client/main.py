import base64
import json
import os
import random
from pathlib import Path
import socket
from cryptographicio import rsa_

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
    server_socket.sendall(message.encode())
    while True:
        data = server_socket.recv(1024)
        if not data:
            break
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


def main():
    global SERVER_PU, PU, PR
    SERVER_PU = rsa_.load_public_key(Path("client/keys/server"))

    while True:
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

        handshake(PU, PR, SERVER_PU)
        # response = send_request("/login", {"username": username, "password": password}, PR, SERVER_PU)
        # if response == "success":
        #     break


if __name__ == "__main__":
    main()
