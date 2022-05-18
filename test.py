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
    answer['qname_bytes'] = bytearray()
    qname = ''
    qname_index = 1
    question_index = 1
    while qname_length > 0:
        for qname_octet in range(qname_index, qname_index + qname_length, 1):
            c = chr(question[qname_octet])
            qname += c
            question_index += 1
        qname_index += qname_length + 1
        qname_length = question[qname_index - 1]
        answer['qname_length'] += qname_length
        question_index += 1
    answer['qname_bytes'] = question[:question_index]
    answer['qname'] = qname
    question_index += 1
    qtype = chr(question[question_index]) + chr(question[1 + question_index])
    answer['qtype'] = qtype
    question_index += 2
    qclass = chr(question[question_index]) + chr(question[1 + question_index])
    answer['qclass'] = qclass
    question_index += 2

    return answer, question_index


def parse_dns_answer_authority_additional(rr):
    answer = dict()
    if (rr[0] & 0b11000000) == 0b11000000:
        print('ptr')
        answer['name'] = ''
        index = 1
    else:
        name_length = rr[0]
        # answer['name_length'] = name_length
        name = ''
        index = 1
        while name_length > 0:
            for name_octet in range(index, index + name_length, 1):
                c = chr(rr[name_octet])
                name += c
            index = index + name_length + 1
            name_length = rr[index - 1]
        # name_length += 1
        answer['name'] = name
    _type = rr[index: index + 2]
    index += 2
    answer['type'] = _type
    _class = rr[index: index + 2]
    index += 2
    answer['class'] = _class
    # ttl = (rr[index] << (8 * 3)) + (rr[1 + index] <<
    #                                 (8 * 2)) + (rr[2 + index] << (8)) + rr[3 + index]
    ttl = (rr[index] << 24) + (rr[1 + index] << 16) + \
        (rr[2 + index] << 8) + rr[3 + index]
    answer['ttl'] = ttl
    index += 4
    rdlength = (rr[index] << 8) + rr[1 + index]
    answer['rdlength'] = rdlength
    index += 2
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

    query_header_dict, query_index = parse_dns_header(query)
    query_question_dict, _query_index = parse_dns_question(query[query_index:])
    query_index += _query_index
    query_additional_index = query_index
    query_additional_dict, _query_index = parse_dns_answer_authority_additional(
        query[query_index:])
    query_index += _query_index
    print(query_header_dict)
    print(query_question_dict)
    print(query_additional_dict)
    qname_length = query_question_dict['qname_length']
    print('qname_length:', qname_length)
    qname = query_question_dict['qname']
    # for qname_octet in range(13, 13 + qname_length, 1):
    #     c = chr(query[qname_octet])
    #     qname += c
    print('qname:', qname)
    # qtype = (query[13 + qname_length] << 8) + query[14 + qname_length]
    qtype = query_question_dict['qtype']
    print('qtype:', qtype)
    # qclass = chr(query[15 + qname_length]) + chr(query[16 + qname_length])
    qclass = query_question_dict['qclass']
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

    # for j in range(len(query) - 1, 0, -1):
    #     for i in range(7, 0, -1):
    #         bit = query[j] >> i & 1
    #         print(bit, end='')
    # print()
    response = bytearray(query)
    # ar_name_length = response[17 + qname_length]
    # print('ar_name_length:', ar_name_length)
    # ar_name = ''
    # for i in response[18 + qname_length: 18 + qname_length + ar_name_length]:
    #     ar_name += chr(i)
    # print('ar_name:', ar_name)
    # rdlength_index = ar_name_length + 18 + qname_length + 4
    # response[rdlength_index] = 4
    # response[rdlength_index + 1] = 142
    # response[rdlength_index + 2] = 250
    # response[rdlength_index + 3] = 74
    # response[rdlength_index + 4] = 206

    # for i in response[17 + qname_length:rdlength_index + 1]:
    #     rr.append(i)

    # for i in query[12: 13 + qname_length]:
    #     rr.append(i)
    # rr.append(1)
    # rr.append(query[query_additional_index])
    # <name>
    domain_name = qname
    # for i in query_question_dict['qname_bytes']:
    #     rr.append(i)
    # rr.append(len(query_question_dict['qname_bytes']) - 1)
    # rr.append(1)
    rr.append(0b11000000)
    rr.append(12)
    # rr.append(0)
    # rr.append(0)
    # rr.append(0)
    # rr.append(0)
    # rr.append(0)
    # rr.append(len(domain_name))
    # for i in domain_name:
    #     rr.append(ord(i))
    # rr.append(1 + len(qclass))
    # for i in qtype[1:]:
    #     rr.append(ord(i))
    # for i in qclass:
    #     rr.append(ord(i))
    # rr.append(0)
    # for i in query[query_index: query_index + 12]:
    #     rr.append(i)
    # </name>

    # # <type>
    # rr[3 + qname_length]
    # rr.append(0)
    # rr.append(1)
    # rr.append(0)
    # rr.append(1)
    # rr.append(192)
    # rr.append(12)
    # rr.append(0)
    rr.append(0)
    rr.append(1)
    # rr.append(query_additional_dict['type'][0])
    # rr.append(query_additional_dict['type'][1])
    # rr.append(0)
    # # rr.append(ord('c'))
    # # # </type>

    # # # <class>
    # rr.append(query_additional_dict['class'][0])
    # rr.append(query_additional_dict['class'][1])
    # rr.append(0)
    # rr.append(0)
    rr.append(0)
    rr.append(1)
    # rr.append(1)
    # # rr.append(ord('o'))
    # # rr.append(ord('m'))
    # # # </class>

    # <ttl>
    # rr.append(0)
    # rr[-2] = 1
    # rr[-1] = 0
    rr.append(0)
    rr.append(0)
    rr.append(1)
    rr.append(44)
    # </ttl>

    # <rdlength>
    # response[17 + qname_length + len(rr)] = 4
    rr.append(0)
    rr.append(4)
    # </rdlength>

    # <rdata>
    # google's ip address is 142.250.74.206
    # response[17 + qname_length + len(rr)] = 142
    rr.append(142)
    # response[17 + qname_length + len(rr)] = 250
    rr.append(250)
    # response[17 + qname_length + len(rr)] = 74
    rr.append(74)
    # response[17 + qname_length + len(rr)] = 206
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
    # response[3] = 0b00000000
    # response[4] = 0
    # response[5] = 1
    response[6] = 0
    response[7] = 1
    # response[8] = 0
    # response[9] = 1
    # response[10] = 0
    # response[11] = 1
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
    # print(parse_dns_answer_authority_additional(rr))
    # to_send = response[:17 + qname_length] + rr + response[17 + qname_length:]
    header_dict, next_index = parse_dns_header(response)
    question_dict, _next_index = parse_dns_question(response[next_index:])
    next_index += _next_index
    to_send = response[:next_index - 1] + rr + response[next_index - 1:]
    print('next_index:', next_index)
    # additional_dict, next_index = parse_dns_answer_authority_additional(response[next_index:])
    # print(to_send)
    next_index = 0
    header_dict, next_index = parse_dns_header(to_send)
    question_dict, _next_index = parse_dns_question(to_send[next_index:])
    next_index += _next_index
    # answer_dict, _next_index = parse_dns_answer_authority_additional(
    #     to_send[next_index:])
    # next_index += _next_index
    # print(header_dict)
    # print(question_dict)
    # print(answer_dict)
    sock_queries.sendto(to_send, address)
    # sock_queries.sendto(response[:17 + qname_length] +
    #                     rr + response[17 + qname_length:], address)
    # sock_queries.sendto(response[:17 + qname_length] + rr, address)
    # sock_queries.sendto(response + rr, address)

    # # <client>
    # sock_client.sendto(bytearray(query), ('8.8.8.8', 53))
    # dns_response = sock_client.recvfrom(10000)
    # for index, _i in enumerate(zip(dns_response[0], to_send)):
    #     i, i2 = _i
    #     print(index, i, i2)
    # header_dict, next_index = parse_dns_header(dns_response[0])
    # question_dict, next_index = parse_dns_question(
    #     dns_response[0][next_index:])
    # print(rr)
    # print(dns_response[0][next_index:])
    # for index, _i in enumerate(zip(dns_response[0][next_index:], rr)):
    #     i, i2 = _i
    #     print(index, int(i), int(i2))
    # answer_dict, next_index = parse_dns_answer_authority_additional(
    #     dns_response[0][next_index:])
    # print(header_dict)
    # print(question_dict)
    # print(next_index)
    # print(answer_dict)
    # # </client>

    # print(bytearray(dns_response[0]))
    # print(to_send)
    # print(parse_dns_header(dns_response[0][:12]))
    # print(parse_dns_header(to_send[:12]))
    # sock_queries.sendto(response + rr, address)
