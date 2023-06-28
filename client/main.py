import argparse
import socket


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-p", "--port", type=int, help="Port number", default=2004)
    arg_parser.add_argument("-h", "--host", type=str, help="Host", default="127.0.0.1")
    args = arg_parser.parse_args()
    port = args.port
    host = args.host

    client_multi_socket = socket.socket()
    try:
        client_multi_socket.connect((host, port))
    except socket.error as e:
        print(str(e))
    res = client_multi_socket.recv(1024)
    while True:
        Input = input("Hey there: ")
        client_multi_socket.send(str.encode(Input))
        res = client_multi_socket.recv(1024)
        print(res.decode("utf-8"))
    client_multi_socket.close()


if __name__ == "__main__":
    main()
