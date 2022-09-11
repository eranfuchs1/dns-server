import socket
import copy


def bits_to_num(bits):
    num = 0
    for i, ri in zip(range(len(bits)), range((len(bits) - 1) * 8, -8, -8)):
        num += bits[i] << ri
    return num


def parse_dns_header(message):
    answer = dict()
    answer['id'] = bits_to_num(message[0:2])
    answer['qr'] = (message[2] >> 7) & 1
    answer['opcode'] = message[2] & 0b01111000
    answer['aa'] = message[2] & 0b00000100
    answer['tc'] = message[2] & 0b00000010
    answer['rcode'] = message[3] & 0b00001111
    answer['qdcount'] = bits_to_num(message[4:6])
    answer['ancount'] = bits_to_num(message[6:8])
    answer['nscount'] = bits_to_num(message[8:10])
    answer['arcount'] = bits_to_num(message[10:12])

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
    return [answer, index]


def read_name_or_pointer(data, index):
    if (data[index] & 0b11000000) == 0b11000000:
        pointer_bytes = data[index:index + 2]
        _index = bits_to_num(
            bytes([pointer_bytes[0] & 0b0011_1111, pointer_bytes[1]]))
        # index = ((data[index] & 0b00111111) << 8) + data[index + 1]
        read_name_output = read_name(data, _index)
        read_name_output[0] = {**read_name_output[0],
                               'pointer_bytes': pointer_bytes}
        return read_name_output[0], index + 2
    return read_name(data, index)


def parse_dns_question(message, index):
    answer = dict()
    name_dict, index = read_name_or_pointer(message, index)
    answer = {**answer, **name_dict}
    # answer['qtype'] = chr(data[index]) + \
    #     chr(data[1 + index])
    answer['qtype'] = message[index:index + 2]
    index += 2
    # answer['qclass'] = chr(data[index]) + \
    #     chr(data[1 + index])
    answer['qclass'] = message[index:index + 2]
    index += 2

    return answer, index


def parse_dns_answer_authority_additional(message, index):
    answer = dict()
    name_dict, index = read_name_or_pointer(message, index)
    answer = {**answer, **name_dict}
    answer['type'] = message[index: index + 2]
    index += 2
    answer['class'] = message[index: index + 2]
    index += 2
    # answer['ttl'] = (message[index] << 24) + (message[1 + index] << 16) + \
    #     (message[2 + index] << 8) + message[3 + index]
    answer['ttl'] = bits_to_num(message[index:index+4])
    index += 4
    rdlength = bits_to_num(message[index: index + 2])
    answer['rdlength'] = rdlength
    index += 2
    rdata = []
    for i in range(index, index + rdlength, 1):
        if len(message) <= i:
            break
        rdata.append(int(message[i]))
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


def get_word(words: list, _codes: dict):
    for i in _codes:
        if i in words:
            return words.index(i)
    return -1


def parse_master_file(fname, ext_origin=''):
    _class_codes = {'IN': b'\x00\x01'}
    _type_codes = {'A': b'\x00\x01',
                   'SOA': b'\x00\x06', 'CNAME': num_to_uint16(5), 'MX': num_to_uint16(15)}
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
            _class_index = get_word(line, _class_codes)
            _type_index = get_word(line, _type_codes)
            _type = line[_type_index]
            rdata = line[_type_index + 1:]
            if _class_index >= 0:
                _class = line[_class_index]
                if _type_index - 1 == _class_index:
                    if _class_index > 0:
                        if line[_class_index - 1].isdigit():
                            ttl = int(line[_class_index - 1])
                        else:
                            domain_name = parse_domain_name(
                                line[0], origin, ext_origin)
                else:
                    ttl = int(line[_class_index + 1])
                    if _class_index > 0:
                        domain_name = parse_domain_name(
                            line[0], origin, ext_origin)
            else:
                if _type_index == 2:
                    ttl = int(line[1])
                    domain_name = parse_domain_name(
                        line[0], origin, ext_origin)
                elif line[0].isdigit():
                    if ttl == int(line[0]):
                        domain_name = parse_domain_name(
                            line[0], origin, ext_origin)
                    else:
                        ttl = int(line[0])
                else:
                    domain_name = parse_domain_name(
                        line[0], origin, ext_origin)
            # if len(line) == 5 + soa_addition:
            #     domain_name = parse_domain_name(line[0], origin, ext_origin)
            #     if str(line[1]).isnumeric():
            #         ttl = int(line[1])
            #         _class = line[2]
            #     else:
            #         ttl = int(line[2])
            #         _class = line[1]
            #     _type = line[3]
            #     rdata = line[4:]
            # elif len(line) == 4 + soa_addition:
            #     if str(line[0]).isupper():
            #         _class = line[0]
            #         ttl = int(line[1])
            #     elif not str(line[0]).isdigit():
            #         domain_name = parse_domain_name(
            #             line[0], origin, ext_origin)
            #         if str(line[1]).isdigit():
            #             ttl = int(line[1])
            #         else:
            #             _class = line[1]
            #     else:
            #         ttl = int(line[0])
            #         _class = line[1]
            #     _type = line[2]
            #     rdata = line[3:]
            # elif len(line) == 3 + soa_addition:
            #     if str(line[0]).isnumeric():
            #         ttl = int(line[0])
            #     elif str(line[0]).isupper():
            #         _class = line[0]
            #     else:
            #         domain_name = parse_domain_name(
            #             line[0], origin, ext_origin)
            #     _type = line[1]
            #     rdata = line[2:]
            # elif len(line) == 2 + soa_addition:
            #     _type = line[0]
            #     rdata = line[1:]
            # else:
            #     raise Exception(
            #         f'incompatible number of arguments in line, {len(line)}', str(line))
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


def parse_cname(records):
    aliases = {}
    for record in records:
        if record['type'] == num_to_uint16(5):
            aliases[record['domain']] = record['rdata'][0]
    return aliases


def answer_question(data, index, records, aliases):
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
                if question_dict['name'] in aliases:
                    if not question_dict['qtype'] == num_to_uint16(6):
                        if aliases[question_dict['name']] == record['domain']:
                            matching_record = record
                            break
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
    elif matching_record['type'] == num_to_uint16(15):
        preference = num_to_uint16(int(matching_record['rdata'][0]))
        mx_domain_bytes = domain_name_to_bytes(matching_record['rdata'][1])
        for b in num_to_uint16(len(preference) + len(mx_domain_bytes)):
            rr.append(b)
        for b in preference:
            rr.append(b)
        for b in mx_domain_bytes:
            rr.append(b)
    return rr, index


def get_remote_record(message):
    _types = {1: 'A', 15: 'MX', 5: 'CNAME', 6: 'SOA'}
    header_dict, index = parse_dns_header(message)
    question_dict, index = parse_dns_question(message, index)
    answer_index = index
    answer_dict, index = parse_dns_answer_authority_additional(message, index)
    answer = {'domain': question_dict['name'], 'class': answer_dict['class'],
              'ttl': answer_dict['ttl'], 'type': answer_dict['type'], 'rdata': bytes(num_to_uint16(answer_dict['rdlength']) + bytes(answer_dict['rdata']))}
    _type = _types[bits_to_num(answer_dict['type'])]
    if _type == 'A':
        rdata_bytes = answer['rdata']
        answer['rdata'] = ['.'.join([str(int(b)) for b in rdata_bytes[2:6]])]
    elif _type == 'CNAME':
        rdata_bytes = answer['rdata']
        # _domain = read_name_or_pointer(message, answer_index  )
        _domain = ''
        index = 3
        _label_length = int(rdata_bytes[index - 1])
        while _label_length > 0:
            for b in rdata_bytes[index: index + _label_length]:
                _domain += ascii(b)
            _domain += '.'
            index += _label_length
            _label_length = int(rdata_bytes[index - 1])

        answer['rdata'] = [_domain]
    elif _type == 'SOA':
        rdata_bytes = copy.deepcopy(answer['rdata'])
        print(answer)
        answer['rdata'] = []
        _domain = ''
        index = 3
        lli_eq_index = False
        _label_length = int(rdata_bytes[index - 1])
        for i in range(2):
            while _label_length > 0:
                if (_label_length & 0b1100_0000) == 0b1100_0000:
                    _ptr = bits_to_num(
                        bytes([_label_length & 0b0011_1111, rdata_bytes[index]]))
                    print(_ptr)
                    _domain += read_name_or_pointer(message, _ptr)[0]['name']
                    index += 1
                    _label_length = int(rdata_bytes[index])
                    lli_eq_index = True
                    break
                if lli_eq_index:
                    index += 1
                for b in rdata_bytes[index: index + _label_length]:
                    _domain += chr(b)
                _domain += '.'
                index += _label_length + 1
                print(index, _label_length)
                _label_length = int(rdata_bytes[index - 1])
                lli_eq_index = False
            answer['rdata'].append(_domain)
            _domain = ''

        # index += 2
        # _label_length = int(rdata_bytes[index - 1])
        # while _label_length > 0:
        #     for b in rdata_bytes[index: index + _label_length]:
        #         _domain += ascii(b)
        #     _domain += '.'
        #     index += _label_length + 1
        #     _label_length = int(rdata_bytes[index - 1])
        # answer['rdata'].append(_domain)

        index += 1
        for i in range(5):
            answer['rdata'].append(
                bits_to_num(rdata_bytes[index + (i*4): index + (i * 4) + 4]))

    return answer


def write_record(fname, record):
    _types = {1: 'A', 15: 'MX', 5: 'CNAME', 6: 'SOA'}
    _classes = {1: 'IN'}
    print(record)
    with open(fname, 'a') as f:
        f.write(f'''
{record['domain']} {_classes[bits_to_num(record['class'])]} {record['ttl']} {_types[bits_to_num(record['type'])]} {' '.join([str(i) for i in record['rdata']])}
''')


def dns_server(records):
    sock_queries = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_queries.bind(('0.0.0.0', 53))
    client_sock_queries = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    aliases = parse_cname(records)
    while True:
        query, address = sock_queries.recvfrom(512)# max size of dns query is 512 octets

        response = bytearray(query)
        response[2] = 0b10000000
        response[7] = 1
        header_dict, index = parse_dns_header(response)
        rr, index = answer_question(query, index, records, aliases)
        if not len(rr):
            print('not found, using remote.')
            client_sock_queries.sendto(query, ('1.1.1.1', 53))
            remote_dns_response, remote_address = client_sock_queries.recvfrom(
                512)# max size of dns response is 512 octets
            sock_queries.sendto(remote_dns_response, address)
            try:
                records.append(get_remote_record(remote_dns_response))
                write_record('cached_zone_file', records[-1])
            except Exception as e:
                print(e)
            continue
        to_send = response[:index] + rr + response[index:]
        sock_queries.sendto(to_send, address)


if __name__ == '__main__':
    import sys
    records = parse_master_file(
        sys.argv[1]) + parse_master_file('cached_zone_file')
    dns_server(records)
