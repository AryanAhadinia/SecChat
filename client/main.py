import argparse
import json
import socket


from ..cryptographicio import rsa


HOST = "127.0.0.1"
UPSTREAM_PORT = 8080
DOWNSTREAM_PORT = 8085

SERVER_PU = rsa.load_public_key("keys/rsa.pub")


def request(address, payload):
    """
    This function is for HTTP like request to the server
    """
    server_socket = socket.socket()
    server_socket.connect((HOST, UPSTREAM_PORT))
    # creating http like message
    http_like_message = {
        "address": address,
        "payload": payload,
    }
    http_like_message_json = json.dumps(http_like_message)
    # signing message with client's private key
    signed_message = {
        "message": http_like_message_json,
        "signature": rsa.sign(http_like_message_json, PR),
        "public_key": PU,
    }
    signed_message_json = json.dumps(signed_message)
    # encrypting message with server's public key
    encrypted_message = rsa.encrypt(signed_message_json, SERVER_PU)
    # sending message to the server
    server_socket.sendall(encrypted_message.encode())
    # receiving response from the server
    res = ""
    while True:
        data = server_socket.recv(1024)
        if not data:
            break
        res += data
    server_socket.close()
    return res


def main():
    server_socket = establish_connection(host, port)

    message


if __name__ == "__main__":
    main()
