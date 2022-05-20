import socket

sock_queries = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock_queries.bind(('0.0.0.0', 53))


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
        name += '.'
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
    # answer['qtype'] = chr(data[index]) + \
    #     chr(data[1 + index])
    answer['qtype'] = data[index:index + 2]
    index += 2
    # answer['qclass'] = chr(data[index]) + \
    #     chr(data[1 + index])
    answer['qclass'] = data[index:index + 2]
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


def parse_master_file_line(line: str):
    try:
        comment_index = line.index(';')
    except ValueError:
        comment_index = -1
    return (line[: comment_index] if comment_index > 0 else line).rstrip('\n').replace('\t', ' ').split(' ')


def remove_parentheses(word: str):
    index = 0
    while index < len(word):
        if word[index] in '()':
            if index > 0:
                if word[index - 1] == '\\':
                    pass
                else:
                    del word[index]
                    continue
            else:
                del word[index]
                continue
        index += 1
    return word


def parse_master_file_lines(lines: list[str]):
    parentheses_queue = []
    answer = []
    words = []
    for line in lines:
        _words = parse_master_file_line(line)
        for word in _words:
            for c in word:
                if c == '(':
                    parentheses_queue.append('(')
                elif c == ')':
                    parentheses_queue.pop()
        words += [remove_parentheses(word)
                  for word in filter(lambda w: not w in '()', _words)]
        if len(parentheses_queue) == 0:
            answer.append(words.copy())
            words = []
    return answer


def parse_domain_name(name, origin, ext_origin):
    if name[-1] == '.':
        return name
    elif name == '@':
        return origin + ext_origin
    else:
        return f'{name}.{origin}{ext_origin}'


def parse_master_file(fname, ext_origin=''):
    _class_codes = {'IN': b'\x00\x01'}
    _type_codes = {'A': b'\x00\x01',
                   'SOA': b'\x00\x06', 'CNAME': num_to_uint16(5)}
    records = []
    with open(fname, 'r') as f:
        lines = parse_master_file_lines(f.readlines())
    origin = ''
    relative_origin = ''
    ttl = 0
    _class = ''
    domain_name = ''
    soa = True
    for line in lines:
        if len(line) == 0:
            continue
        index = 0
        word = line[index]
        soa_addition = soa * 6
        if word == '$ORIGIN':
            index += 1
            word = line[index]
            origin = parse_domain_name(word, origin, ext_origin)
            continue
        elif word == '$INCLUDE':
            index += 1
            word = line[index]
            records += parse_master_file(word, origin + ext_origin)
            continue
        else:
            if len(line) == 5 + soa_addition:
                domain_name = parse_domain_name(line[0], origin, ext_origin)
                if str(line[1]).isnumeric():
                    ttl = int(line[1])
                    _class = line[2]
                else:
                    ttl = int(line[2])
                    _class = line[1]
                _type = line[3]
                rdata = line[4:]
            elif len(line) == 4 + soa_addition:
                if str(line[0]).isupper():
                    _class = line[0]
                    ttl = int(line[1])
                elif not str(line[0]).isdigit():
                    domain_name = parse_domain_name(
                        line[0], origin, ext_origin)
                    if str(line[1]).isdigit():
                        ttl = int(line[1])
                    else:
                        _class = line[1]
                else:
                    ttl = int(line[0])
                    _class = line[1]
                _type = line[2]
                rdata = line[3:]
            elif len(line) == 3 + soa_addition:
                if str(line[0]).isnumeric():
                    ttl = int(line[0])
                elif str(line[0]).isupper():
                    _class = line[0]
                else:
                    domain_name = parse_domain_name(
                        line[0], origin, ext_origin)
                _type = line[1]
                rdata = line[2:]
            elif len(line) == 2 + soa_addition:
                _type = line[0]
                rdata = line[1:]
            else:
                raise Exception(
                    f'incompatible number of arguments in line, {len(line)}', str(line))
            if soa:
                soa = False
            for i, data in enumerate(rdata):
                if data == '@':
                    rdata[i] = parse_domain_name(data, origin, ext_origin)
            records.append({'domain': domain_name, 'ttl': ttl,
                            'class': _class_codes[_class], 'type': _type_codes[_type], 'rdata': rdata})
    return records


def num_to_bits(num, bits):
    return bytes(bytearray([((num >> bit) & 0b11111111) << bit for bit in range(bits-8, -8, -8)]))


def num_to_uint16(num):
    # return bytes(bytearray([((num >> 8) & 0b11111111) << 8, num & 0b11111111]))
    return num_to_bits(num, 16)


def num_to_uint32(num):
    return num_to_bits(num, 32)


def domain_name_to_bytes(domain_name):
    domain_name_bytes = bytearray()
    for cell in domain_name.rstrip('.').split('.'):
        domain_name_bytes.append(len(cell))
        for c in cell:
            domain_name_bytes.append(ord(c))
    domain_name_bytes.append(0)
    return bytes(domain_name_bytes)


def answer_question(data, index, records):
    # header_dict, index = parse_dns_header(data)
    question_dict, index = parse_dns_question(data, index)
    print(question_dict)
    matching_record = None
    for record in records:
        print(record)
        if question_dict['qtype'] == record['type']:
            print('qtype match')
            if question_dict['qclass'][1] == record['class'][1]:
                print('qclass match')
                if question_dict['name'] == record['domain']:
                    print('name match')
                    matching_record = record
                    break
    if not matching_record:
        return bytearray(), index

    rr = bytearray()  # `rr` := resource record
    # <name>
    rr.append(0b11000000)
    rr.append(12)
    # </name>

    # <type>
    # rr += bytearray(matching_record['type'])
    rr.append(matching_record['type'][0])
    rr.append(matching_record['type'][1])
    # rr.append(0)
    # rr.append(1)
    # </type>

    # <class>
    # rr += matching_record['class']
    rr.append(matching_record['class'][0])
    rr.append(matching_record['class'][1])
    # rr.append(0)
    # rr.append(1)
    # </class>

    # <ttl>
    rr.append((int(matching_record['ttl']) & (
        0b11111111 << 24)) >> 24)
    rr.append((int(matching_record['ttl']) & (
        0b11111111 << 16)) >> 16)
    rr.append((int(matching_record['ttl']) & (
        0b11111111 << 8)) >> 8)
    rr.append((int(matching_record['ttl']) & (
        0b11111111)))
    # rr.append(0)
    # rr.append(0)
    # rr.append(1)
    # rr.append(44)
    # </ttl>

    # <rdlength>

    # rr.append((len(matching_record['rdata']) & (
    #     0b11111111 << 8)) >> 8)
    # rr.append((len(matching_record['rdata']) & (
    #     0b11111111)))

    # rr.append(0)
    # rr.append(4)
    # </rdlength>

    # <rdata>
    if matching_record['type'] == b'\x00\x01':
        rr.append(0)
        rr.append(4)
        for i in str(matching_record['rdata'][0]).split('.'):
            rr.append(int(i))
    elif matching_record['type'] == b'\x00\x06':
        rr.append(0)
        rr.append(
            20 + sum([sum(len(cell) + 1 for cell in rdata_cell.rstrip('.').split('.')) + 1 for rdata_cell in matching_record['rdata'][0:2]]))
        for rdata_cell in matching_record['rdata'][0].rstrip('.').split('.'):
            print(rdata_cell)
            print('rdata_cell length:', len(rdata_cell))
            rr.append(len(rdata_cell))
            for c in rdata_cell:
                rr.append(ord(c))
        rr.append(0)
        for rdata_cell in matching_record['rdata'][1].rstrip('.').split('.'):
            rr.append(len(rdata_cell))
            for c in rdata_cell:
                rr.append(ord(c))
        rr.append(0)
        for i in matching_record['rdata'][2:]:
            for j in [24, 16, 8, 0]:
                rr.append((int(i) & (0b11111111 << j)) >> j)
        # for i in range(20):
        #     rr.append(0)
    elif matching_record['type'] == num_to_uint16(5):
        cname_bytes = domain_name_to_bytes(matching_record['rdata'][0])
        for b in num_to_uint16(len(cname_bytes)):
            rr.append(b)
        for b in cname_bytes:
            rr.append(b)
    return rr, index


def dns_server(records):
    while True:
        query, address = sock_queries.recvfrom(1000)

        response = bytearray(query)
        response[2] = 0b10000000
        response[7] = 1
        header_dict, index = parse_dns_header(response)
        rr, index = answer_question(query, index, records)
        if not len(rr):
            print('error')
            response[3] = (response[3] & 0b11110000) + 2
        to_send = response[:index] + rr + response[index:]
        sock_queries.sendto(to_send, address)


if __name__ == '__main__':
    import sys
    records = parse_master_file(sys.argv[1])
    dns_server(records)
