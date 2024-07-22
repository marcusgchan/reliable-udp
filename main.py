import socket


def main():
    pass


class Server:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def listen(self, host: str, port: int):
        self.socket.bind((host, port))
        self.socket.listen()
        while True:
            connection, _ = self.socket.accept()
            with connection:
                data, sender = connection.recvfrom(4096)
                print("data", data)
                print("sender", sender)


if __name__ == "__main__":
    main()
