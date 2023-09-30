import socket
import struct
import UDPTOTCP
import random

data_store = "" # concatenates all the data received during a connection

# Create UDP socket
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('localhost', 10000)
server.bind(('localhost', 10000))
print('waiting')


# Establish UDTCP connection - 3-way handshake
# Waiting for SYN packet & seq_num of client (x in lecture)
seq_num = 0  # y -- initialize server's sequence number
seq_num, ack_num = UDPTOTCP.handshake_server(server,seq_num)
# ---- end of 3-way handshake



# RECEIVE AND SEND DATA

while True:
    if UDPTOTCP.server_state == 0:
        data, client_address = server.recvfrom(1024)
        flags, client_seq_num, client_ack_num, client_check_sum = struct.unpack("!IIII", data[:UDPTOTCP.tcp_header_size])

        if flags & UDPTOTCP.fin_bit:
            UDPTOTCP.end_connect_server(server, client_seq_num, client_ack_num, client_address)
            break

        # In case of receiving a request
        checksum = UDPTOTCP.calculate_checksum(data[UDPTOTCP.tcp_header_size:])
        if checksum == client_check_sum:
            print("All good! transmitted correctly")
            msg = data[UDPTOTCP.tcp_header_size:].decode()
            data_store += msg
            print("Received: ", msg)
            # Send UDTCP ACK packet
            seq_num = client_ack_num + 1
            ack_num = client_seq_num + len(data[UDPTOTCP.tcp_header_size:])
            flags = UDPTOTCP.ack_bit
            ackmsg = "Ack Packet"
            checksum = UDPTOTCP.calculate_checksum(ackmsg.encode())
            header = struct.pack("!IIII", flags, seq_num, ack_num, checksum)
            server.sendto(header + ackmsg.encode(), client_address)

            # moving from transport to application layer
            response = UDPTOTCP.prepare_response(msg)
            print(response)
            UDPTOTCP.server_state = 1
        else:
            print("Corrupt Packet")

    else:  # send response then set state to 1
        # message, client_address = server.recvfrom(1024) #receving dummy message to catch address of client
        checksum = UDPTOTCP.calculate_checksum(response.encode())
        header = struct.pack("!IIII", flags, seq_num, ack_num, checksum)
        packet = header + bytes(response, 'utf-8')
        seq_num += len(response)  # elly hb3to el mra el gya
        ack_num += 1

        while True:
            # simulating packet loss from app layer
            if random.random() < 0.1:  # probability simulation for packet loss
                print("Packet loss")
                continue  # hb3tha hya tany

            server.sendto(packet, client_address)  # send the response el7mdulellah
            print("breaker")
            # timeout:
            try:
                server.settimeout(1)
                data, client_address = server.recvfrom(1024)
                flags, server_seq_num, server_ack_num, server_checksum = struct.unpack("!IIII", data[:UDPTOTCP.tcp_header_size])
                checksum = UDPTOTCP.calculate_checksum(data[UDPTOTCP.tcp_header_size:])

                if flags & UDPTOTCP.ack_bit and server_ack_num == seq_num and checksum == server_checksum:
                    print("All good! transmitted correctly")
                    server.settimeout(None)
                    break
            except socket.timeout:
                print("Timeout")

        print("received", packet[UDPTOTCP.tcp_header_size:].decode())
        ack_num += 1

        UDPTOTCP.server_state = 0


server.close()