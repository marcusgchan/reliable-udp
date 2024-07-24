import socket
import struct
import sys


def main():
    address_to_binary("127.0.0.1")
    encoded_packet = attach_headers("127.0.0.1", "192.168.1.102", 8000, 80, 0, 0, 0b0010, 500, "Hello World!")
    packet = struct.unpack("!IIHHIIBH24s", encoded_packet)
    print(packet)
    # app_type = sys.argv[1]
    # if app_type == "server":
    #     init_server(int(sys.argv[2]))
    # elif app_type == "client":
    #     init_client("127.0.0.1", int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))


def init_client(host: str, port: int, dest_host: str, dest_port: int):
    client = Client()
    client.start(host, port, dest_host, dest_port)


def init_server(port: int):
    server = Server()
    server.listen("127.0.0.1", port)

def split_packets(data: str, mss: int) -> list[str]:
    print("Splits data based on the MSS")

def address_to_binary(address: str):
    nums = address.split(".")
    binary = ""
    for num in nums:
        binary += format(int(num), '08b')
        # would have to attach the binary to each binary, we can also just do something else
    print(binary)
    print(int(binary, 2))
    print(bin(int(binary, 2)))
    return int(binary, 2)

def binary_to_address(data: int) -> str:
    binary_string = bin(data)[2:]
    return binary_string

def attach_headers(src_addr: str, dst_addr: str, src_port: int, dst_port: int, seq: int, ack: int, flags: bytes, window: int, msg="") -> bytes:
    # Header is: Src_addr(32), Dst_addr(32), Src_port(16), Dst_port(16), seq #(32), ack #(32), Flags(8), Window(16), Length (16)
    bin_src = address_to_binary(src_addr)
    bin_dst = address_to_binary(dst_addr)
    header = struct.pack("!IIHHIIBH", bin_src, bin_dst, src_port, dst_port, seq, ack, flags, window)
    # Here we would add the data
    data = struct.pack("24s", msg.encode('utf-8')) # instead of 24 it would be the MSS
    packet = header + data
    # print("Header: ", header)
    # print("Message: ", msg.encode('utf-8'))
    # print("Data: ", data)
    # print("Packet: ", packet)
    return packet

class Server:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def listen(self, host: str, port: int):
        self.socket.bind((host, port))
        while True:
            data, sender = self.socket.recvfrom(4096)
            self.unpack(data, sender)
            print("data", data)
            print("sender", sender)

    def unpack(self, encoded_packet: bytes, sender):
        data = struct.unpack("!IIHHIIBH24s", encoded_packet)
        print("Received from buffer: ", data)
        newmsg = attach_headers("127.0.0.1", "192.168.1.102", 8000, 80, 0, 0, 0b0010, 500, "Hello World!")
        self.socket.sendto(newmsg, sender)

class Client:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def start(self, host: str, port: int, dest_host: str, dest_port: int):
        self.socket.bind((host, port))
        # After binding, proceed to handshaking
        syn = attach_headers(host, dest_host, port, dest_port, 0, 0, 0b0010, 0)
        self.send(syn, dest_host, dest_port, True)
        ack = attach_headers(host, dest_host, port, dest_port, 0, 0, 0b0100, 0)
        self.send(ack, dest_host, dest_port, False)
        while True:
            val = input("msg: ")
            packet = attach_headers(host, dest_host, port, dest_port, 0, 0, 0b0100, 0, val)
            self.socket.sendto(packet, (dest_host, dest_port))

    def send(self, msg: bytes, dest_host: str, dest_port: int, wait_for_ack: bool):
        self.socket.sendto(msg, dest_host, dest_port)
        print("Client sent SYN")
        ack = not wait_for_ack
        while not ack:
            msg, _ = self.socket.recvfrom(4096)
            if msg:
                unpacked_msg = struct.unpack("!IIHHIIBHp", msg)
                print(unpacked_msg)
                ack = True

"""
Handshaking:
1. Client sends segment with Flags SYN set
2. Server is running and receives a message, if flags SYN is set, proceed to handshake -> answer with Flags SYN and ACK set and with a MSS
3. Client sends segment with Flags ACK set after it has received the SYNACK
"""

"""
Sending:
1. Receive data from "application layer"
2. Split into packets based on MSS
3. Attach header to packet --> this includes calculating the seq #, ack #, and checksum
4. Send segment
5. Start timer
6. Repeat 3, 4, and 5 based on the window size
7.a. If timeout and no response from other party with corresponding ACK, redo 3, 4, 5 for packet
7.b. Else, move window
"""

"""
Receiving:
1. Receive data from lower layer
2. Unpack data and count checksum, compare with checksum value in headers
3.a. If data is corrupted, don't buffer it
3.b. If data is not corrupted, send an ACK and buffer data
    --> I was thinking we could buffer data on a hash map (key is seq # and val is data), so it is easy to re-order out of order packets (get all keys and sort the keys)
4. Send data to application layer
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
