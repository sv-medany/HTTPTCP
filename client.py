import socket
import struct
import random
import UDPTOTCP

# Create UDP socket
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('localhost', 10000)

# Establish TCP connection - 3-way handshake
seq_num = 0  # x - initializing sequence number of client
seq_num, ack_num = UDPTOTCP.handshake_client(seq_num, client, server_address)
# end of 3-way handshake

# Send data using UDTCP packets

while True:

    if UDPTOTCP.client_state == 0:

        # request input format:
        # python client.py post /test.txt "This is a test."
        # python client.py get /test.txt

        request_input = input("Enter message: ")
        message = UDPTOTCP.request_message_prompt_handling(request_input)

        if message == 'quit':
            # End Connection
            UDPTOTCP.end_connect_client(client, seq_num, ack_num, server_address)
            break

        # Send requests & wait for response
        # checksum in TCP is only computed for data, therefore we only use it in actual data transfer, neither connection establishment or closing

        flags = 0
        # assume that request will never exceed 1024 byte, therefore it'll be 1 packet so 1 ack number is expected
        checksum = UDPTOTCP.calculate_checksum(message.encode())
        header = struct.pack("!IIII", flags, seq_num, ack_num, checksum)
        packet = header + bytes(message, 'utf-8')
        seq_num += len(message)  # bta3 awel packet fe array packets elly hb3tha

        # sending the prepared packet & handle retransmission in case of timeout or corrupt ack
        while True:
            # simulating packet loss from app layer
            if random.random() < UDPTOTCP.packet_loss_rate:  # probability simulation for packet loss
                print("Packet loss")
                continue  # tries again
            client.sendto(packet, server_address)
            # timeout:
            try:
                client.settimeout(UDPTOTCP.timeout)
                data, server_address = client.recvfrom(1024)  # waiting for the ack
                flags, server_seq_num, server_ack_num, server_checksum = struct.unpack("!IIII", data[ :UDPTOTCP.tcp_header_size])

                checksum = UDPTOTCP.calculate_checksum(data[UDPTOTCP.tcp_header_size:])
                if flags & UDPTOTCP.ack_bit and server_ack_num == seq_num and checksum == server_checksum:
                    print("All good! transmitted correctly")
                    ack_num += 1  # making sure that received correctly, therefore increment after it not before
                    client.settimeout(None)
                    break
            except socket.timeout:
                print("timeout")

        print("received", packet[UDPTOTCP.tcp_header_size:].decode())
        UDPTOTCP.client_state = 1

    else: #waiting for response
        print("waiting for response")
        # client.sendto("dummy".encode(),server_address) # dummy message for the server to catch the client's address

        data, server_address = client.recvfrom(1024)
        flags, server_seq_num, server_ack_num, server_check_sum = struct.unpack("!IIII", data[:UDPTOTCP.tcp_header_size])

        # handling actual data:
        checksum = UDPTOTCP.calculate_checksum(data[UDPTOTCP.tcp_header_size:])
        if checksum == server_check_sum:
            print("All good! transmitted correctly")
            msg = data[UDPTOTCP.tcp_header_size:].decode()
            print("RESPONSE: ", msg)
            # Send UDTCP ACK packet
            seq_num = server_ack_num
            ack_num = server_seq_num + len(data[UDPTOTCP.tcp_header_size:])
            flags = UDPTOTCP.ack_bit
            ackmsg = "Ack Packet"
            checksum = UDPTOTCP.calculate_checksum(ackmsg.encode())
            header = struct.pack("!IIII", flags, seq_num, ack_num, checksum)
            client.sendto(header + ackmsg.encode(), server_address)
        else:
            print("Corrupt Packet at client")
        UDPTOTCP.client_state = 0

client.close()