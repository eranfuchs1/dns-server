import socket

sock_queries = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock_queries.bind(('127.0.0.1', 5300))

while True:
    byte_count = 1000
    query, address = sock_queries.recvfrom(byte_count)
    print(address)
    print(query)
    print(len(query) * 4)
    id = (query[0] << 8) + query[1]
    print('id:', id)
    qr = query[2] >> 7 & 1
    opcode = (query[2] & 0b01111000)
    rcode = query[3] & 0b00001111
    qdcount = (query[4] << 8) + query[5]
    ancount = (query[6] << 8) + query[7]
    nscount = (query[8] << 8) + query[9]
    arcount = (query[10] << 8) + query[11]
    print('id:', id)
    print('qr:', qr)
    print('opcode:', opcode)
    print('rcode:', rcode)
    print('qdcount:', qdcount)
    print('ancount:', ancount)
    print('nscount:', nscount)
    print('arcount:', arcount)

    qname_length = query[12]
    print('qname_length:', qname_length)
    for qname_octet in range(13, 13 + qname_length, 1):
        print(chr(query[qname_octet]))

    for j in range(len(query) - 1, 0, -1):
        for i in range(7, 0, -1):
            bit = query[j] >> i & 1
            print(bit, end='')
    print()
    response = bytearray(query)
    response[2] = 0b10000000
    response[3] = 0b00000010
    for j in range(len(response) - 1, 0, -1):
        for i in range(7, 0, -1):
            bit = response[j] >> i & 1
            print(bit, end='')
    print()
    qr_response = response[2] >> 7 & 1
    rcode_response = response[3] & 0b00001111
    print('qr_response:', qr_response)
    print('rcode_response:', rcode_response)
    sock_queries.sendto(response, address)
