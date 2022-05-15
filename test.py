import ctypes
import socket

sock_queries = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock_queries.bind(('127.0.0.1', 5300))

while True:
    byte_count = 1000  # 131?
    query, address = sock_queries.recvfrom(byte_count)
    # if len(query) < byte_count:
    #     continue
    print(address)
    print(query)
    print(len(query) * 4)
    # id = query[0:4]
    # print(bin(query[0]), bin(query[1]), bin(query[2]), bin(query[3]))
    id = (query[0] << 8) + query[1]
    print('id:', id)
    # id = 0
    # for index, i in enumerate(reversed(query[0:4])):
    #     print('bin(i):', bin(i))
    #     left_shift = (((index - 1) * 4))
    #     if left_shift < 0:
    #         left_shift = 0
    #     num = (i << left_shift)
    #     print(num)
    #     print(bin(num))
    #     id += num
    # id += i
    # id = id & 0b0111111111111111
    qr = query[2] >> 7 & 1
    # opcode = (query[2] & 0b0111 << 3) + query[5] >> 3 & 1
    opcode = (query[2] & 0b01111000)
    rcode = query[3] & 0b00001111
    # for i in query[8:12]:
    #     print('i:', i)
    # qdcount = bin((query[8] << 11) + (query[9] << 7) + (query[10] << 3) + query[11])
    qdcount = (query[4] << 8) + query[5]
    # bin((query[12] << 11) + (query[13] << 7) + (query[14] << 3) + query[15])
    ancount = (query[6] << 8) + query[7]
    # bin((query[16] << 11) + (query[17] << 7) + (query[18] << 3) + query[19])
    nscount = (query[8] << 8) + query[9]
    # bin((query[20] << 11) + (query[21] << 7) + (query[22] << 3) + query[23])
    arcount = (query[10] << 8) + query[11]
    # for index, i in enumerate(reversed(query[8:12])):
    #     left_shift = ((index * 4) - 1)
    #     if left_shift < 0:
    #         left_shift = 0
    #     qdcount += (i << left_shift)
    # for index, i in enumerate(reversed(query[12:16])):
    #     left_shift = ((index * 4) - 1)
    #     if left_shift < 0:
    #         left_shift = 0
    #     ancount += (i << left_shift)
    # for index, i in enumerate(reversed(query[16:20])):
    #     left_shift = ((index * 4) - 1)
    #     if left_shift < 0:
    #         left_shift = 0
    #     nscount += (i << left_shift)
    # for index, i in enumerate(reversed(query[20:24])):
    #     left_shift = ((index * 4) - 1)
    #     if left_shift < 0:
    #         left_shift = 0
    #     arcount += (i << left_shift)
    print('id:', id)
    print('qr:', qr)
    print('opcode:', opcode)
    print('rcode:', rcode)
    print('qdcount:', qdcount)
    print('ancount:', ancount)
    print('nscount:', nscount)
    print('arcount:', arcount)
    for j in range(len(query) - 1, 0, -1):
        for i in range(7, 0, -1):
            bit = query[j] >> i & 1
            print(bit, end='')
    print()
    response = bytearray(query)
    response[2] = 0b10000000
    response[3] = 0b00000010
    # response[7] = 1
    # _response_ancount = 60
    # response[15] = _response_ancount >> 12
    # response[14] = _response_ancount >> 8
    # response[13] = _response_ancount >> 4
    # response[14] = _response_ancount
    # query[4] = 0b1000
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
