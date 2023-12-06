import statistics


class Header:
    def __init__(self, id, flags, qd_count, an_count, ns_count, ar_count):
        self.id = id
        self.flags = flags
        self.qd_count = qd_count
        self.an_count = an_count
        self.ns_count = ns_count
        self.ar_count = ar_count

class Question:
    def __init__(self, name, _type, _class):
        self.name = name
        self.type = _type
        self._class = _class

class ResourceRecord:
    def __init__(self, name, _type, _class, ttl, lenght_data, data):
        self.name = name
        self.type = _type
        self._class = _class
        self.ttl = ttl
        self.lenght_data = lenght_data
        self.data = data

class DNSMessedge:
    def __init__(self, header, question, answer, authority, additional):
        self.header = header
        self.question = question
        self.answer = answer
        self.authority = authority
        self.additional = additional

    def convert_byte_in_int(self, bytes):
        return int.from_bytes(bytes, byteorder='big')


def give_usual_query(data):
    header = b'\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    return data[0:2] + header + data[len(header) + 2:]


