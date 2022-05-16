import socket

sock_queries = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock_queries.bind(('127.0.0.1', 5300))

sock_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def parse_dns_header(header):
    answer = dict()
    id = (header[0] << 8) + header[1]
    answer['id'] = id
    qr = (header[2] >> 7) & 1
    answer['qr'] = qr
    opcode = header[2] & 0b01111000
    answer['opcode'] = opcode
    aa = header[2] & 0b00000100
    answer['aa'] = aa
    tc = header[2] & 0b00000010
    answer['tc'] = tc
    rcode = header[3] & 0b00001111
    answer['rcode'] = rcode
    qdcount = (header[4] << 8) + header[5]
    answer['qdcount'] = qdcount
    ancount = (header[6] << 8) + header[7]
    answer['ancount'] = ancount
    nscount = (header[8] << 8) + header[9]
    answer['nscount'] = nscount
    arcount = (header[10] << 8) + header[11]
    answer['arcount'] = arcount

    return answer, 12


def parse_dns_question(question):
    answer = dict()
    qname_length = question[0]
    answer['qname_length'] = qname_length
    qname = ''
    for qname_octet in range(1, 1 + qname_length, 1):
        c = chr(question[qname_octet])
        qname += c
    answer['qname'] = qname
    qtype = chr(question[1 + qname_length]) + chr(question[2 + qname_length])
    answer['qtype'] = qtype
    qclass = chr(question[3 + qname_length]) + chr(question[4 + qname_length])
    answer['qclass'] = qclass

    return answer, 5 + qname_length


def parse_dns_answer_authority_additional(rr):
    answer = dict()
    name_length = rr[1]
    # answer['name_length'] = name_length
    name = ''
    index = 2
    while name_length > 0:
        for name_octet in range(index, index + name_length, 1):
            c = chr(rr[name_octet])
            name += c
        index = index + name_length + 1
        print(index)
        name_length = rr[index - 1]
        print(name_length)
    # name_length += 1
    answer['name'] = name
    _type = rr[index: index + 2]
    index += 3
    answer['type'] = _type
    _class = rr[index: index + 2]
    index += 9
    answer['class'] = _class
    # ttl = (rr[index] << (8 * 3)) + (rr[1 + index] <<
    #                                 (8 * 2)) + (rr[2 + index] << (8)) + rr[3 + index]
    ttl = (rr[index] << 8) + rr[1 + index]
    answer['ttl'] = ttl
    index += 3
    rdlength = rr[index]
    answer['rdlength'] = rdlength
    index += 1
    rdata = []
    for i in range(index, index + rdlength, 1):
        if len(rr) <= i:
            break
        rdata.append(int(rr[i]))
    answer['rdata'] = rdata
    return answer, index + rdlength


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
    print(parse_dns_header(query[:12]))

    qname_length = query[12]
    print('qname_length:', qname_length)
    qname = ''
    for qname_octet in range(13, 13 + qname_length, 1):
        c = chr(query[qname_octet])
        qname += c
    print('qname:', qname)
    # qtype = (query[13 + qname_length] << 8) + query[14 + qname_length]
    qtype = chr(query[13 + qname_length]) + chr(query[14 + qname_length])
    print('qtype:', qtype)
    qclass = chr(query[15 + qname_length]) + chr(query[16 + qname_length])
    print('qclass:', qclass)

    rr = bytearray()  # `rr` := resource record
    # <qname>
    # rr.append(len('google.com'))
    # for c in 'google.com':
    #     rr.append(ord(c))
    # for qn in range(12, 13 + qname_length):  # `qn` := qname
    #     rr.append(query[qn])
    # </qname>

    # <type>
    # # 0b100101100
    # rr.append(0b100101100 >> 8)
    # rr.append(0b100101100 & 0b11111111)
    # rr.append(0)
    # rr.append(1)
    # </type>

    # <class>
    # rr.append(ord('I'))
    # rr.append(ord('N'))
    # rr.append(0)
    # rr.append(1)
    # </class>

    # <ttl>
    # rr.append(0b00000000)
    # rr.append(0b00000000)
    # </ttl>

    # <rdlength>
    # rr.append(4)
    # # </rdlength>

    # # <rdata>
    # # google's ip address is 142.250.74.206
    # rr.append(142)
    # rr.append(250)
    # rr.append(74)
    # rr.append(206)
    # </rdata>

    for j in range(len(query) - 1, 0, -1):
        for i in range(7, 0, -1):
            bit = query[j] >> i & 1
            print(bit, end='')
    print()
    response = bytearray(query)
    ar_name_length = response[17 + qname_length]
    print('ar_name_length:', ar_name_length)
    ar_name = ''
    for i in response[18 + qname_length: 18 + qname_length + ar_name_length]:
        ar_name += chr(i)
    print('ar_name:', ar_name)
    rdlength_index = ar_name_length + 18 + qname_length + 4
    # response[rdlength_index] = 4
    # response[rdlength_index + 1] = 142
    # response[rdlength_index + 2] = 250
    # response[rdlength_index + 3] = 74
    # response[rdlength_index + 4] = 206

    # for i in response[17 + qname_length:rdlength_index + 1]:
    #     rr.append(i)

    for i in query[12: 13 + qname_length]:
        rr.append(i)
    # <name>
    # domain_name = 'google'
    # rr.append(len(domain_name))
    # for i in domain_name:
    #     rr.append(ord(i))
    # </name>

    # # <type>
    # rr[3 + qname_length]
    rr.append(0)
    # rr.append(ord('c'))
    # # </type>

    # # <class>
    rr.append(0)
    # rr.append(ord('o'))
    # rr.append(ord('m'))
    # # </class>

    # <ttl>
    rr.append(0)
    rr.append(0)
    # rr[-2] = 1
    # rr[-1] = 0
    # </ttl>

    # <rdlength>
    rr.append(4)
    # </rdlength>

    # <rdata>
    # google's ip address is 142.250.74.206
    rr.append(142)
    rr.append(250)
    rr.append(74)
    rr.append(206)
    # </rdata>
    # for index, i in enumerate(rr):
    #     response[index + 17 + qname_length] = i
    # for index, i in enumerate(query[16 + qname_length:len(query)]):
    #     response[index] = 0
    #     print(i, end='')
    print(response[17 + qname_length])
    print()
    response[2] = 0b10000000
    response[3] = 0b00000000
    # response[4] = 0
    # response[5] = 1
    response[6] = 0
    response[7] = 1
    response[10] = 0
    response[11] = 1
    for j in range(len(response) - 1, 0, -1):
        for i in range(7, 0, -1):
            bit = response[j] >> i & 1
            print(bit, end='')
    print()
    qr_response = response[2] >> 7 & 1
    rcode_response = response[3] & 0b00001111
    print('qr_response:', qr_response)
    print('rcode_response:', rcode_response)
    # sock_queries.sendto(response[:13 + qname_length] +
    #                     rr + response[13 + qname_length:], address)
    to_send = response[:17 + qname_length] + rr + response[17 + qname_length:]
    sock_queries.sendto(to_send, address)
    # sock_queries.sendto(response[:17 + qname_length] +
    #                     rr + response[17 + qname_length:], address)
    # sock_queries.sendto(response[:17 + qname_length] + rr, address)
    # sock_queries.sendto(response + rr, address)
    sock_client.sendto(bytearray(query), ('8.8.8.8', 53))
    dns_response = sock_client.recvfrom(10000)
    header_dict, next_index = parse_dns_header(dns_response[0])
    question_dict, next_index = parse_dns_question(
        dns_response[0][next_index:])
    answer_dict, next_index = parse_dns_answer_authority_additional(
        dns_response[0][next_index:])
    print(header_dict)
    print(question_dict)
    print(answer_dict)
    # print(bytearray(dns_response[0]))
    # print(to_send)
    # print(parse_dns_header(dns_response[0][:12]))
    # print(parse_dns_header(to_send[:12]))
    # sock_queries.sendto(response + rr, address)
