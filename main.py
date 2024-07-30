import socket
import random
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
    if app_type == "client":
        init_client("127.0.0.1", int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))


def init_client(host: str, port: int, dest_host: str, dest_port: int):
    client = Client()
    client.start(host, port, dest_host, dest_port)


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
    # print("Received from address (in read_headers): ", headers.src_addr)
    raw_data = b"";
    index_of_end = data[9].find(b'\r')
    if index_of_end == -1:
        raw_data = data[9]
    else:
        raw_data = data[9][:index_of_end+1]
        
    return headers, raw_data.rstrip(b"\x00")

        
class Client:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.stream = io.BytesIO()
        self.stream_mut = threading.Lock()
        self.stream_index = 0

        self.waiting_packets: dict[int, tuple[bytes, socket._Address]] = {} # waiting to be acked
        self.waiting_packets_mut = threading.Lock()
        self.waiting_packets_sig = threading.Event()

        self.timer = threading.Timer(0.9, self.handle_timer)
        self.timer_mut = threading.Lock()

        self.next_seq_num = 0
        self.next_seq_num_mut = threading.Lock()

        self.init_seq_num = 0

        self.ack_num = 0
        self.init_ack_num = 0

        self.is_connected = False
        self.is_connected_mut = threading.Lock()

        self.received_syn = False

        self.rwnd = 6 # receiver window size
        self.rwnd_mut = threading.Lock()

        self.cwnd = 6 # window size
        self.cwnd_mut = threading.Lock()

        self.mss = 2  # we can set the MSS using a flag from the server but yeah

        self.ssthresh = 10
        self.ssthresh_mut = threading.Lock()

        self.buffer = b""
        self.buffer_mut = threading.Lock()
        self.max_buffer_size = 256

    def start(self, host: str, port: int, dest_host: str, dest_port: int):
        self.host = host
        self.port = port
        self.dest_host = dest_host
        self.dest_port = dest_port

        self.socket.bind((host, port))

        # Spawn new thread for receving acks
        recv_thread = threading.Thread(target=self.handle_receive)
        recv_thread.start()

        # Spawn thread for user input
        input_thread = threading.Thread(target=self.handle_input)
        input_thread.start()

        while True:
            self.waiting_packets_sig.wait()

            with self.cwnd_mut:
                cwnd = self.cwnd

            with self.waiting_packets_mut:
                with self.rwnd_mut:
                    if min(cwnd, self.rwnd) > self.mss:
                        remaining_spots = int(min(cwnd, self.rwnd) // self.mss) - len(self.waiting_packets)
                        bytes_to_read = remaining_spots * self.mss
                    else:
                        remaining_spots = min(cwnd, self.rwnd)
                        bytes_to_read = remaining_spots

            with self.stream_mut:
                self.stream.seek(self.stream_index)
                bytes_to_split = self.stream.read(bytes_to_read)
                if len(bytes_to_split) == 0:
                    self.waiting_packets_sig.clear()
                    continue

            self.stream_index += len(bytes_to_split)
            
            for i in range(0, len(bytes_to_split), self.mss):
                # print("seq", self.seq_num + len(input_bytes[:i]))
                body = bytes_to_split[i:i+self.mss]
                
                with self.next_seq_num_mut:
                    packet_seq_num = self.next_seq_num
                    self.next_seq_num += len(body)

                print(f"sending data={body} seq_num={packet_seq_num}")

                with self.buffer_mut:
                    packet = attach_headers(host, dest_host, port, dest_port, packet_seq_num, self.ack_num, b'0000', self.max_buffer_size -  len(self.buffer), body)

                with self.waiting_packets_mut:
                    self.waiting_packets[packet_seq_num] = packet, (dest_host, dest_port)

                with self.timer_mut:
                    if i == 0 and not self.timer.is_alive():
                        self.timer = threading.Timer(0.9, self.handle_timer)
                        self.timer.start()
                        print("Starting timer in send")

                self.sendto(packet, (dest_host, dest_port))


    def handle_timer(self):
        print("Timer ran out... Resending packets. halfing sstresh and setting cwnd back to MMS (Multiplicative Decrease)")

        # Congestion control
        with self.ssthresh_mut:
            with self.cwnd_mut:
                self.ssthresh = min(self.cwnd // 2, 1)
                self.cwnd = self.mss

        with self.waiting_packets_mut:
            for _, value in self.waiting_packets.items():
                packet, address = value
                self.sendto(packet, address)

        with self.timer_mut:
            self.timer = threading.Timer(0.9, self.handle_timer)
            self.timer.start()

    def handle_receive(self):
        while True:
            raw_data, address = self.socket.recvfrom(4096)
            dest_host, dest_port = address
            unpacked_data = struct.unpack("!IIHHII4sHH24s", raw_data)
            headers, raw_data = read_headers(unpacked_data)

            with self.is_connected_mut:
                if not self.is_connected:
                    # SYN
                    if headers.flags.syn and not headers.flags.ack and not self.received_syn:
                        print("Received syn")
                        self.rwnd = headers.window
                        self.received_syn = True
                        self.init_ack_num = headers.seq_num + 1
                        self.ack_num = headers.seq_num + 1
                        synack = attach_headers(self.host, dest_host, self.port, dest_port, self.init_seq_num, headers.seq_num + 1, b'0110', self.max_buffer_size)
                        self.sendto(synack, (dest_host, dest_port))
                        with self.next_seq_num_mut:
                            next_seq_num = self.next_seq_num
                        with self.waiting_packets_mut:
                            self.waiting_packets[next_seq_num] = synack, (dest_host, dest_port)
                            self.next_seq_num += 1
                        with self.timer_mut:
                            self.timer = threading.Timer(0.9, self.handle_timer)
                            self.timer.start()

                    # SYNACK
                    elif headers.flags.syn and headers.ack_num == self.init_seq_num + 1:
                        print("Received synack")
                        self.rwnd = headers.window
                        self.init_ack_num = headers.seq_num + 1
                        self.ack_num = headers.seq_num + 1
                        ack = attach_headers(self.host, dest_host, self.port, dest_port, 0, headers.seq_num + 1, b'0100', self.max_buffer_size)
                        self.sendto(ack, (dest_host, dest_port))
                        with self.timer_mut:
                            self.timer.cancel()
                        with self.next_seq_num_mut:
                            print(f"Established connection. seq_n={self.next_seq_num} ack_n={self.ack_num}")
                        self.is_connected = True

                    # Handshake ACK
                    elif headers.ack_num == self.init_seq_num + 1:
                        print("Received handshake ack")
                        with self.waiting_packets_mut:
                            del self.waiting_packets[self.init_seq_num]
                            with self.timer_mut:
                                self.timer.cancel()
                        with self.next_seq_num_mut:
                            print(f"Established connection. seq_n={self.next_seq_num} ack_n={self.ack_num}")
                        self.is_connected = True

                else:
                    with self.buffer_mut:
                        # Received wrong packet
                        if headers.seq_num != self.ack_num:
                            with self.next_seq_num_mut:
                                ack = attach_headers(self.host, dest_host, self.port, dest_port, self.next_seq_num, self.ack_num, b'0100', self.max_buffer_size - len(self.buffer))
                            self.sendto(ack, (dest_host, dest_port))
                            continue

                        # Received data
                        if not headers.flags.ack:
                            with self.rwnd_mut:
                                self.rwnd = headers.window

                            # Flow control
                            print(f"buffer_len={len(self.buffer)} received_len={len(raw_data)}")
                            if len(self.buffer) + len(raw_data) > self.max_buffer_size:
                                print("buffer before overflow", self.buffer)
                                overflow = len(self.buffer) + len(raw_data) - self.max_buffer_size
                                # drop bytes from start of buffer (simple but bad flow control algo)
                                self.buffer = self.buffer[overflow:]
                                print("Buffer overflowing! Truncating start of buffer")

                            self.buffer += raw_data
                            self.ack_num += len(raw_data)

                            # Obtained full msg
                            if chr(self.buffer[-1]) == "\r":
                                print("msg from client:", self.buffer.decode())
                                self.buffer = b""

                            buffer_space = self.max_buffer_size - len(self.buffer)

                            # set buffer to 1 if there's no space as a simple measure to prevent deadlock
                            window = 1 if buffer_space == 0 else buffer_space

                            with self.next_seq_num_mut:
                                ack = attach_headers(self.host, dest_host, self.port, dest_port, self.next_seq_num, self.ack_num, b'0100', window)
                            self.sendto(ack, (dest_host, dest_port))

                        # Received ack
                        else:
                            with self.rwnd_mut:
                                self.rwnd = headers.window
                            ack_num = headers.ack_num

                            with self.waiting_packets_mut:
                                keys_to_remove = [key for key in self.waiting_packets if key < ack_num]
                                for key in keys_to_remove:
                                    del self.waiting_packets[key]

                            # Congestion control
                            with self.cwnd_mut:
                                with self.ssthresh_mut:
                                    with self.rwnd_mut:
                                        # Congestion avoidance
                                        if self.ssthresh >= self.cwnd:
                                            if self.cwnd + self.mss * (self.mss / self.cwnd) <= self.rwnd:
                                                print(f"Congestion avoidance... Additive increase. cwnd={self.cwnd}")
                                                self.cwnd += self.mss * (self.mss / self.cwnd)
                                        else:
                                            if self.cwnd + self.mss <= self.rwnd:
                                                self.cwnd += self.mss
                                                print(f"Slow start. Adding mms to cwnd cwnd={self.cwnd}")

                            self.waiting_packets_sig.set()

                            with self.waiting_packets_mut:
                                if len(self.waiting_packets) > 0:
                                    print("Restarting timer")
                                    with self.timer_mut:
                                        self.timer.cancel()
                                        self.timer = threading.Timer(0.9, self.handle_timer)
                                        self.timer.start()
                                else:
                                    print("Stopping timer")
                                    with self.timer_mut:
                                        self.timer.cancel()

    def handle_input(self):
        while True:
            val = input("")

            with self.is_connected_mut:
                is_connected = self.is_connected

            if val == "!connect":
                syn = attach_headers(self.host, self.dest_host, self.port, self.dest_port, self.init_seq_num, 0, b'0010', self.max_buffer_size)
                with self.waiting_packets_mut:
                    with self.next_seq_num_mut:
                        self.waiting_packets[self.next_seq_num] = syn, (self.dest_host, self.dest_port)
                        self.next_seq_num += 1
                        self.sendto(syn, (self.dest_host, self.dest_port))
                        with self.timer_mut:
                            self.timer = threading.Timer(0.9, self.handle_timer)
                            self.timer.start()
            elif not is_connected:
                print("Not Connected!. Type !connect to initialize handshake")
            else:
                val += "\r"
                input_bytes = val.encode()
                with self.stream_mut:
                    self.stream.write(input_bytes)
                self.waiting_packets_sig.set()


    """
    Simulate loss
    """
    def sendto(self, readableBuffer: bytes, address: Any) -> int:
        randint = random.randint(1, 10)
        if randint > 1:
            return self.socket.sendto(readableBuffer, address)
        return -1


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
