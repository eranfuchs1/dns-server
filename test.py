import socket

sock_queries = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock_queries.bind(('127.0.0.1', 5300))


def parse_dns_header(header):
    answer = dict()
    answer['id'] = (header[0] << 8) + header[1]
    answer['qr'] = (header[2] >> 7) & 1
    answer['opcode'] = header[2] & 0b01111000
    answer['aa'] = header[2] & 0b00000100
    answer['tc'] = header[2] & 0b00000010
    answer['rcode'] = header[3] & 0b00001111
    answer['qdcount'] = (header[4] << 8) + header[5]
    answer['ancount'] = (header[6] << 8) + header[7]
    answer['nscount'] = (header[8] << 8) + header[9]
    answer['arcount'] = (header[10] << 8) + header[11]

    return answer, 12


def read_name(data, index):
    s_index = index
    name_length = data[index]
    name = ''
    index += 1
    while name_length > 0:
        for name_octet in range(index, index + name_length, 1):
            c = chr(data[name_octet])
            name += c
        index = index + name_length + 1
        name_length = data[index - 1]
    answer = {'name': name, 'name_bytes': data[s_index:index]}
    return answer, index


def read_name_or_pointer(data, index):
    if (data[index] & 0b11000000) == 0b11000000:
        pointer_bytes = data[index:index + 2]
        index = ((data[index] & 0b00111111) << 8) + data[index + 1]
        read_name_output = read_name(data, index)
        read_name_output[0] = {**read_name_output[0],
                               'pointer_bytes': pointer_bytes}
        return read_name_output[0], index
    return read_name(data, index)


def parse_dns_question(data, index):
    answer = dict()
    name_dict, index = read_name_or_pointer(data, index)
    answer = {**answer, **name_dict}
    answer['qtype'] = chr(data[index]) + \
        chr(data[1 + index])
    index += 2
    answer['qclass'] = chr(data[index]) + \
        chr(data[1 + index])
    index += 2

    return answer, index


def parse_dns_answer_authority_additional(data):
    answer = dict()
    name_dict, index = read_name_or_pointer(data, index)
    answer = {**answer, **name_dict}
    answer['type'] = data[index: index + 2]
    index += 2
    answer['class'] = data[index: index + 2]
    index += 2
    answer['ttl'] = (data[index] << 24) + (data[1 + index] << 16) + \
        (data[2 + index] << 8) + data[3 + index]
    index += 4
    rdlength = (data[index] << 8) + data[1 + index]
    answer['rdlength'] = rdlength
    index += 2
    rdata = []
    for i in range(index, index + rdlength, 1):
        if len(data) <= i:
            break
        rdata.append(int(data[i]))
    answer['rdata'] = rdata
    index += rdlength
    return answer, index


while True:
    query, address = sock_queries.recvfrom(1000)

    rr = bytearray()  # `rr` := resource record
    response = bytearray(query)
    # <name>
    rr.append(0b11000000)
    rr.append(12)
    # </name>

    # <type>
    rr.append(0)
    rr.append(1)
    # </type>

    # <class>
    rr.append(0)
    rr.append(1)
    # </class>

    # <ttl>
    rr.append(0)
    rr.append(0)
    rr.append(1)
    rr.append(44)
    # </ttl>

    # <rdlength>
    rr.append(0)
    rr.append(4)
    # </rdlength>

    # <rdata>
    # google's ip address is 142.250.74.206
    rr.append(142)
    rr.append(250)
    rr.append(74)
    rr.append(206)
    # </rdata>
    response[2] = 0b10000000
    response[7] = 1
    header_dict, index = parse_dns_header(response)
    question_dict, index = parse_dns_question(response, index)
    to_send = response[:index] + rr + response[index:]
    sock_queries.sendto(to_send, address)
