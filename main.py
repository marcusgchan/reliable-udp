import socket
import struct
import sys
from dataclasses import dataclass

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


def init_client(host: str, port: int, dest_host: str, dest_port: int):
    client = Client()
    client.start(host, port, dest_host, dest_port)


def init_server(port: int):
    server = Server()
    server.listen("127.0.0.1", port)

def divide_binary_string(s: str, n: int):
    return [s[i:i+n] for i in range(0, len(s), n)]

def split_packets(data: str, buffer: list[bytes], seq_num: int) -> list[bytes]:
    print("Splits data into bytes to fit it in the array")
    buffer = divide_binary_string(data.encode(), 8)
    buffer.append('\r'.encode())
    return buffer
    # Iterate through message, dividing it into bytes, adding each byte to the array
    # Try not to overflow buffer
    # How do we know what can we overwrite?

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

def attach_headers(src_addr: str, dst_addr: str, src_port: int, dst_port: int, seq: int, ack: int, flags: bytes, window: int, msg="") -> bytes:
    # Header is: Src_addr(32), Dst_addr(32), Src_port(16), Dst_port(16), seq #(32), ack #(32), Flags(8), Window(16), checksum (16)
    bin_src = address_to_binary(src_addr)
    bin_dst = address_to_binary(dst_addr)
    # -------------------------Calculate checksum here----------------------------------------
    checksum = 0
    header = struct.pack("!IIHHIIBHH", bin_src, bin_dst, src_port, dst_port, seq, ack, flags, window, checksum)
    data = struct.pack("24s", msg.encode('utf-8')) # instead of 24 it would be the MSS
    packet = header + data
    return packet

def read_headers(data: bytes):
    #Src_addr, Dst_addr, Src_port, Dst_port, seq #(32), ack #(32), Flags(8), Window(16), checksum
    headers = Header
    headers.src_addr = binary_to_address(data[0])
    headers.dst_addr = binary_to_address(data[1])
    headers.src_port = data[2]
    headers.dst_port = data[3]
    headers.seq_num = data[4]
    headers.ack_num = data[5]
    flags_bin = bin(data[6])
    flags = Flag
    flags.push = flags_bin[-4] == '1'
    flags.ack = flags_bin[-3] == '1'
    flags.syn = flags_bin[-2] == '1'
    flags.fin = flags_bin[-1] == '1'
    headers.flags = flags
    headers.window = data[7]
    headers.checksum = data[8]
    print("Received from address (in read_headers): ", headers.src_addr)
    print("Received to current (in read_headers): ", headers.dst_addr)
    print("Flags (in read_headers): ", flags)
    return headers, data[9].decode()

class Server:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        connections = {}
        # How do we track the seq nums and ACK? Like do we do for diff connections?

    def listen(self, host: str, port: int):
        self.socket.bind((host, port))
        print("Server is listening in port:", port)
        while True:
            data, sender = self.socket.recvfrom(4096)
            self.unpack(data, sender)
            print("Sender: ", sender)

    def unpack(self, encoded_packet: bytes, sender):
        data = struct.unpack("!IIHHIIBHH24s", encoded_packet)
        print("Received from buffer: ", data)
        # Read headers
        headers, msg = read_headers(data)
        print("Received message from Client:", msg)
        # Check Source address and source port to see if a connection has been established already
        # -------------------------Check checksum here----------------------------------------
        """
        Checksum is all good, so we need to check what the headers say.
        -> Case 1: syn flag is true. Send back SYNACK and wait for ACK to safe this connection.
        -> Case 2: ack flag is true. We check ack# and seq# to see what it tracks back to.
        
        """
        if headers.flags.syn:
            print("RECEIVED A SYN")
            newmsg = attach_headers("127.0.0.1", "192.168.1.102", 8000, 80, 0, 0, 0b0110, 500, "Sending SYNACK")
            self.socket.sendto(newmsg, sender)
            return
        print("RECEIVED AN ACK")
        newmsg = attach_headers("127.0.0.1", "192.168.1.102", 8000, 80, 0, 0, 0b0110, 500, "Hello World!")
        self.socket.sendto(newmsg, sender)

class Client:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        buffer = [0b00000000] # * SeqNums
        last_seq_num = 0
        last_ack_num = 0
        mss = 60  # we can set the MSS using a flag from the server but yeah
        # Track seq nums and ACK #

    def start(self, host: str, port: int, dest_host: str, dest_port: int):
        self.socket.bind((host, port))
        print("Binding with host")
        # After binding, proceed to handshaking
        syn = attach_headers(host, dest_host, port, dest_port, 0, 0, 0b0010, 0)
        self.send(syn, dest_host, dest_port, True)
        ack = attach_headers(host, dest_host, port, dest_port, 0, 0, 0b0100, 0)
        self.send(ack, dest_host, dest_port, False)
        while True:
            val = input("msg: ")
# -------------------------Split packets here----------------------------------------
            buffer = split_packets(val, self.buffer)
            msg = buffer[self.last_seq_num:self.last_seq_num+self.mss]
            # Increase Seq num and increase ack num
            packet = attach_headers(host, dest_host, port, dest_port, self.last_seq_num, self.last_ack_num, 0b0100, 0, msg)
            self.socket.sendto(packet, (dest_host, dest_port))

    def send(self, msg: bytes, dest_host: str, dest_port: int, wait_for_ack: bool):
        print("Message being sent is: ", msg)
        self.socket.sendto(msg, (dest_host, dest_port))
        ack = not wait_for_ack
        while not ack:
            msg, _ = self.socket.recvfrom(4096)
            if msg:
                unpacked_msg = struct.unpack("!IIHHIIBHH24s", msg)
                headers, msg_rcvd = read_headers(unpacked_msg)
                print("Headers received by client: ", headers)
                print("Message received by client: ", msg_rcvd)
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
