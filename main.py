import socket
import sys


def main():
    app_type = sys.argv[1]
    if app_type == "server":
        init_server(int(sys.argv[2]))
    elif app_type == "client":
        init_client("127.0.0.1", int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))


def init_client(host: str, port: int, dest_host: str, dest_port: int):
    client = Client()
    client.start(host, port, dest_host, dest_port)


def init_server(port: int):
    server = Server()
    server.listen("127.0.0.1", port)


class Server:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def listen(self, host: str, port: int):
        self.socket.bind((host, port))
        while True:
            data, sender = self.socket.recvfrom(4096)
            print("data", data)
            print("sender", sender)


class Client:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def start(self, host: str, port: int, dest_host: str, dest_port: int):
        self.socket.bind((host, port))
        while True:
            val = input("msg: ")
            self.socket.sendto(val.encode(), (dest_host, dest_port))


"""
running client:
python3 main.py client 8001 localhost 8000

python3 main.py client <port> <dest_host> <dest_port> 

running server:
python3 main.py server 8000

python3 main.py server <port>
"""
if __name__ == "__main__":
    main()
