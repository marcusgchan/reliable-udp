import socket
import threading
import struct
import sys
import io
from dataclasses import dataclass
from typing import Any

@dataclass
class Flag:
    push: bool
    ack: bool
    syn: bool
    fin: bool

@dataclass
class Header:
    src_addr: str
    dst_addr: str
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    flags: Flag
    window: int
    checksum: int


def main():
    # address_to_binary("127.0.0.1")
    # encoded_packet = attach_headers("127.0.0.1", "192.168.1.102", 8000, 80, 0, 0, 0b0010, 500, "Hello World!")
    # packet = struct.unpack("!IIHHIIBH24s", encoded_packet)
    # print(packet)
    app_type = sys.argv[1]
    if app_type == "server":
        init_server(int(sys.argv[2]))
    elif app_type == "client":
        init_client("127.0.0.1", int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))


# https://stackoverflow.com/questions/30686701/python-get-size-of-string-in-bytes
def utf8len(s):
    return len(s.encode('utf-8'))

def init_client(host: str, port: int, dest_host: str, dest_port: int):
    client = Client()
    client.start(host, port, dest_host, dest_port)


def init_server(port: int):
    server = Server()
    server.listen("127.0.0.1", port)

def divide_binary_string(s: str, n: int):
    return [s[i:i+n] for i in range(0, len(s), n)]


def address_to_binary(address: str):
    nums = address.split(".")
    binary = ""
    for num in nums:
        binary += format(int(num), '08b')
        # would have to attach the binary to each binary, we can also just do something else
    return int(binary, 2)

def binary_to_address(data: int) -> str:
    binary_string = bin(data)[2:].zfill(32) #32 bits
    substr = divide_binary_string(binary_string, 8)
    addresses = [str(int(b, 2)) for b in substr]
    # Join the decimal numbers with a period
    return '.'.join(addresses)

def attach_headers(src_addr: str, dst_addr: str, src_port: int, dst_port: int, seq: int, ack: int, flags: bytes, window: int, msg = b'') -> bytes:
    # Header is: Src_addr(32), Dst_addr(32), Src_port(16), Dst_port(16), seq #(32), ack #(32), Flags(8), Window(16), checksum (16)
    bin_src = address_to_binary(src_addr)
    bin_dst = address_to_binary(dst_addr)
    # -------------------------Calculate checksum here----------------------------------------
    checksum = 0
    header = struct.pack("!IIHHII4sHH", bin_src, bin_dst, src_port, dst_port, seq, ack, flags, window, checksum)
    data = struct.pack("24s", msg) # instead of 24 it would be the MSS
    packet = header + data
    return packet

def read_headers(data: tuple[Any, ...]) -> tuple[Header, bytes]:
    #Src_addr, Dst_addr, Src_port, Dst_port, seq #(32), ack #(32), Flags(8), Window(16), checksum
    headers = Header
    headers.src_addr = binary_to_address(data[0])
    headers.dst_addr = binary_to_address(data[1])
    headers.src_port = data[2]
    headers.dst_port = data[3]
    headers.seq_num = data[4]
    headers.ack_num = data[5]
    flags_bin = data[6]
    flags = Flag
    flags.push = chr(flags_bin[-4]) == '1'
    flags.ack = chr(flags_bin[-3])  == '1'
    flags.syn = chr(flags_bin[-2])  == '1'
    flags.fin = chr(flags_bin[-1])  == '1'
    headers.flags = flags
    headers.window = data[7]
    headers.checksum = data[8]
    print("Received from address (in read_headers): ", headers.src_addr)
    raw_data = b"";
    index_of_end = data[9].find(b'\r')
    if index_of_end == -1:
        raw_data = data[9]
    else:
        raw_data = data[9][:index_of_end+1]
        
    return headers, raw_data

class Server:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def listen(self, host: str, port: int):
        self.socket.bind((host, port))
        print("Server is listening in port:", port)
        buffer:bytes = b""
        while True:
            raw_data, sender = self.socket.recvfrom(4096)
            unpacked_data = struct.unpack("!IIHHII4sHH24s", raw_data)
            headers, raw_data = read_headers(unpacked_data)

            # Check Source address and source port to see if a connection has been established already
            # -------------------------Check checksum here----------------------------------------
            """
            Checksum is all good, so we need to check what the headers say.
            -> Case 1: syn flag is true. Send back SYNACK and wait for ACK to safe this connection.
            -> Case 2: ack flag is true. We check ack# and seq# to see what it tracks back to.
            
            """
            if headers.flags.syn:
                print("RECEIVED A SYN")
                newmsg = attach_headers("127.0.0.1", "192.168.1.102", 8000, 80, 0, headers.seq_num + 1, b'0110', 500, b"Sending SYNACK")
                self.socket.sendto(newmsg, sender)
                continue
            if headers.flags.ack:
                print("Established connection with", sender)
                continue

            buffer += raw_data

            # Obtained full msg
            if chr(buffer[-1]) == "\r":
                print("msg from client:", buffer.decode())
                buffer = b""

            # Send ack
            ack_packet = attach_headers("127.0.0.1", "192.168.1.102", 8000, 80, 0, headers.seq_num + len(raw_data), b'0010', 500)
            self.socket.sendto(ack_packet, sender)


class Client:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.stream = io.BytesIO()
        self.stream_index = 0

        self.waiting_packets: dict[int, bytes] = {} # waiting to be acked

        self.init_seq_num = 0
        self.seq_num = 0
        self.ack_num = 0
        self.window_size = 6
        self.mss = 2  # we can set the MSS using a flag from the server but yeah
        # Track seq nums and ACK #

    def start(self, host: str, port: int, dest_host: str, dest_port: int):
        self.socket.bind((host, port))

        # After binding, proceed to handshaking
        syn = attach_headers(host, dest_host, port, dest_port, 0, 0, b'0010', 0)
        self.send(syn, dest_host, dest_port, True)
        ack = attach_headers(host, dest_host, port, dest_port, self.seq_num, 0, b'0100', 0)
        self.send(ack, dest_host, dest_port, False)

        print(f"Finished handshake. seq_n={self.seq_num} ack_n={self.ack_num}")

        # Spawn new thread for receving acks
        recv_thread = threading.Thread(target=self.handle_acks)
        # recv_thread.start()

        while True:
            val = input("msg: ")
            val += "\r"
            input_bytes = val.encode()
            self.stream.write(input_bytes)
            self.stream.seek(self.stream_index)

            num_of_packets = self.window_size // self.mss - len(self.waiting_packets)
            bytes_to_split = self.stream.read(num_of_packets * self.mss)
            self.stream_index += self.window_size
            
            for i in range(0, len(bytes_to_split), self.mss):
                # print("seq", self.seq_num + len(input_bytes[:i]))
                body = input_bytes[i:i+self.mss]
                packet_seq_num = self.seq_num + len(input_bytes[:i])
                packet = attach_headers(host, dest_host, port, dest_port, packet_seq_num, self.ack_num, b'0000', 0, body)
                
                # packet_seq_num + len(body) is min ack that will acknowledge the packet
                self.waiting_packets[packet_seq_num + len(body)] = packet

                print("sending data", body)
                self.socket.sendto(packet, (dest_host, dest_port))

            # Increase Seq num and increase ack num
            # packet = attach_headers(host, dest_host, port, dest_port, self.last_seq_num, self.last_ack_num, 0b0100, 0, msg)
            # self.send(packet, dest_host, dest_port)

    def handle_acks(self):
        while True:
            raw_data, sender = self.socket.recvfrom(4096)


    def send(self, msg: bytes, dest_host: str, dest_port: int, wait_for_ack: bool):
        # print("Message being sent is: ", msg)
        self.socket.sendto(msg, (dest_host, dest_port))
        ack = not wait_for_ack
        while not ack:
            msg, _ = self.socket.recvfrom(4096)
            if msg:
                unpacked_msg = struct.unpack("!IIHHII4sHH24s", msg)
                headers, msg_rcvd = read_headers(unpacked_msg)

                # --- Do checksum

                self.seq_num = headers.ack_num

                # check for synack
                if headers.flags.syn and headers.flags.ack:
                    print("Synack is good!")
        # -------------------------Check ACK corresponds here----------------------------------------
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
python3 main.py client 8001 127.0.0.1 8000

python3 main.py client <port> <dest_host> <dest_port> 

running server:
python3 main.py server 8000

python3 main.py server <port>
"""
if __name__ == "__main__":
    main()
