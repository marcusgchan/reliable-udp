import socket
import struct
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

def divide_data(data: str, mss: int) -> list[str]:
    print("Splits data based on the MSS")

def convert_address_to_binary(address: str):
    nums = address.split(".")
    for num,  in nums:
        bin(int(num))
        # would have to attach the binary to each binary, we can also just do something else

def attach_headers(src_addr: str, dst_addr: str, src_port: int, dst_port: int, seq: int, ack: int, flags: bytes, window: int, data) -> bytes:
    # Header is: Src_addr(32), Dst_addr(32), Src_port(16), Dst_port(16), seq #(32), ack #(32), Flags(8), Window(16)
    bin_src = convert_address_to_binary(src_addr)
    bin_dst = convert_address_to_binary(dst_addr)
    header = struct.pack("!IIHHIIBH", bin_src, bin_dst, src_port, dst_port, seq, ack, flags, window)
    # Here we would add the data
    return header

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
        # After binding, proceed to handshaking
        syn = attach_headers(host, dest_host, port, dest_port, 0, 0, 0b0010, 0)
        self.socket.sendto(syn, (dest_host, dest_port))
        self.socket.recvfrom(4096)
        ack = attach_headers(host, dest_host, port, dest_port, 0, 0, 0b0010, 0)
        self.socket.sendto(ack, (dest_host, dest_port))
        while True:
            val = input("msg: ")
            self.socket.sendto(val.encode(), (dest_host, dest_port))

"""
Handshaking:
1. Client sends segment with Flags SYN set
2. Server is running and receives a message, if flags SYN is set, proceed to handshake -> answer with Flags SYN and ACK set and with a MSS
3. Client sends segment with Flags ACK set after it has received the SYNACK
"""

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
