import argparse
import socket
import os
from _thread import *


def multi_threaded_client(connection):
    connection.send(str.encode("Server is working:"))
    while True:
        data = connection.recv(2048)
        print("Client message: " + data.decode("utf-8"))
        response = "Server message: " + data.decode("utf-8")
        if not data:
            break
        connection.sendall(str.encode(response))
    connection.close()


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-p", "--port", type=int, help="Port number", default=2004)
    arg_parser.add_argument("-h", "--host", type=str, help="Host", default="127.0.0.1")
    args = arg_parser.parse_args()
    port = args.port
    host = args.host

    server_side_socket = socket.socket()

    try:
        server_side_socket.bind((host, port))
    except socket.error as e:
        print(str(e))
    print("Socket is listening..")
    server_side_socket.listen(5)
    while True:
        client, address = server_side_socket.accept()
        print("Connected to: " + address[0] + ":" + str(address[1]))
        start_new_thread(multi_threaded_client, (client,))
    server_side_socket.close()


if __name__ == "__main__":
    main()
