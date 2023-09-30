import struct


# handling request/response cycles

# for client:
# 0 --> sending request
# 1 --> waiting for response

# for server:
# 0 --> waiting for request
# 1 --> sending response

server_state = 0
client_state = 0

# Define header fields

tcp_header_size = 16  # 1 byte for flags, 1 for seq_num, 1 for ack_num, 1 for checksum
syn_bit = 0x1
ack_bit = 0x2
fin_bit = 0x4
packet_loss_rate = 0.1  # assumed by us
timeout = 1  # one second assumed by us

def calculate_checksum(data):
    if len(data) % 2 != 0:
        data += b"\x00"  # add a byte (dummy) to be even number of bytes
    checksum = 0
    for i in range(0, len(data), 2):  # 3shan agm3 16 bit w 16 bit
        checksum += (data[i] << 8) + data[i + 1]  # hn2smhom (khlebalak mn step size)
    checksum = (checksum >> 16) + (checksum & 0xffff)  # get carry bit only
    checksum = checksum + (checksum >> 16)  # ehtyaty double one carry
    return ~checksum & 0xffff  # ones complement


def parse_request(request):
    lines = request.split("\r\n")
    method, path, _ = lines[0].split(" ")
    body = None
    for line in lines[1:]:
        if line:
            key, value = line.split(": ")
            if key == "Content-Length":
                body = lines[-1]
                break
    return method, path, body


def handshake_client(seq_num, client, address):
    # step 1:  client only sends his seq_num + sets SYNBIT, no need to send ack
    flags = syn_bit
    header = struct.pack("!II", flags, seq_num)
    client.sendto(header, address)
    seq_num += 1  # increase sequence number to send next packet

    # Wait for SYN-ACK
    while True:
        data, server_address = client.recvfrom(1024)
        flags, server_seq_num, server_ack_num = struct.unpack("!III", data[:tcp_header_size])
        if flags & ack_bit and flags & syn_bit and server_ack_num == seq_num:
            ack_num = server_seq_num + 1  # y+1
            flags = ack_bit
            # step 3: send ACKnum only to establish connection
            header = struct.pack("!II", flags, ack_num)
            client.sendto(header, server_address)
            break

    print("UDTCP connection established with", server_address)
    return seq_num, ack_num


def handshake_server(server, seq_num):
    while True:
        data, client_address = server.recvfrom(1024)
        flags, client_seq_num = struct.unpack("!II", data[:tcp_header_size])
        if flags & syn_bit:  # lw gtly syn bit, hstop waiting we hrod 3la el client
            break

    # step 2: send SYN-ACK packet & seq_num which is y of server & ack_num which is x+1
    ack_num = client_seq_num + 1  # x+1
    flags = syn_bit | ack_bit  # 00000011
    header = struct.pack("!III", flags, seq_num, ack_num)
    server.sendto(header, client_address)

    # waiting for 3rd step: receive ack from client

    while True:
        data, client_address = server.recvfrom(1024)
        flags, client_ack_num = struct.unpack("!II", data[:tcp_header_size])
        if flags & ack_bit and client_ack_num == seq_num + 1:
            seq_num += 1
            break

    print("UDTCP connection established with", client_address)
    return seq_num, ack_num


def request_message_prompt_handling(request):
    method = request.split(" ")[0].upper()
    if method == "GET":
        message = f"GET {request.split(' ')[1]} HTTP/1.0\r\n\r\n"
    elif method == "POST":
        prompt_data = input("Enter Data to send: ")
        message = f"POST {request.split(' ')[1]} HTTP/1.0\r\nContent-Length: {len(prompt_data)}\r\n\r\n{prompt_data}"
    else:
        message = request
    return message


def end_connect_client(client,seq_num,ack_num,server_address):
    # step 1: sends his seq_num and FIN_bit one
    flags = fin_bit
    header = struct.pack("!IIII", flags, seq_num, ack_num, 0)
    client.sendto(header, server_address)

    # Wait for ACK packet
    while True:
        data, server_address = client.recvfrom(1024)
        flags, server_seq_num, server_ack_num = struct.unpack("!III", data[:tcp_header_size])
        if flags & ack_bit and server_ack_num == seq_num + 1:
            break

    # waiting for the fin packet of the server
    while True:
        data, server_address = client.recvfrom(1024)
        flags, server_seq_num, server_ack_num = struct.unpack("!III", data[:tcp_header_size])

        if flags & fin_bit:
            # step 4: end ACK packet
            ack_num = server_seq_num + 1
            seq_num = server_ack_num
            flags = ack_bit
            header = struct.pack("!III", flags, seq_num, ack_num)
            client.sendto(header, server_address)
            break


def end_connect_server(server, client_seq_num, client_ack_num, client_address):
    # Send ACK packet
    ack_num = client_seq_num + 1
    seq_num = client_ack_num
    flags = ack_bit

    # step 2
    header = struct.pack("!III", flags, seq_num, ack_num)
    server.sendto(header, client_address)

    # step 3
    ack_num += 1
    seq_num += 1
    flags = fin_bit
    header = struct.pack("!III", flags, seq_num, ack_num)
    server.sendto(header, client_address)

    # Wait for UDTCP ACK packet
    while True:
        data, server_address = server.recvfrom(1000)
        flags, client_seq_num, client_ack_num = struct.unpack("!III", data[:tcp_header_size])
        if flags & ack_bit and client_ack_num == seq_num + 1:
            break


def prepare_response(msg):
    if not msg.startswith(("GET", "POST")):
        response = f"HTTP/1.0 {400} {'Bad Request'}\r\n\r\n"
    else:
        method, path, body = parse_request(msg)
        if method == "GET":
            try:
                with open(path[1:], "r") as file:
                    content = file.read()  # what we will send in the response
                    response = f"HTTP/1.0 200 OK\r\n\r\n{content}"
            except FileNotFoundError:
                response = f"HTTP/1.0 {404} {'Not Found'}\r\n\r\n"
        elif method == "POST":
            # Handle the post request here
            # For example, store the data sent in the body to a file
            with open(path[1:], "w") as file:
                file.write(body)
                response = f"HTTP/1.0 200 OK\r\n\r\n"
    return response