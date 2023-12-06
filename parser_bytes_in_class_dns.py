from constructs_dns import *


class ParserBytes:

    def __init__(self, query_data):
        self.query_data = query_data
        self.offset_reader = 0
        self.index_end_question_query = 0

    def parse_many(self, func_parse, amount):
        result=[]
        for c in range(amount):
            result.append(func_parse())
        return result

    def parse_byte_in_dns_message(self):
        header = self.parse_header()
        question = self.parse_many(self.parse_question, header.qd_count)
        answer = self.parse_many(self.parse_rr, header.an_count)
        authority = self.parse_many(self.parse_rr, header.ns_count)
        additional = self.parse_many(self.parse_rr, header.ar_count)
        return DNSMessedge(header, question, answer, authority, additional)

    def read_size(self, size):
        result = self.query_data[self.offset_reader: self.offset_reader + size]
        self.offset_reader += size
        return result

    def convert_byte_in_int(self, bytes):
        return int.from_bytes(bytes, byteorder='big')

    def parse_header(self):
        _id = self.read_size(2)
        flags = self.read_size(2)
        qd_count = self.convert_byte_in_int(self.read_size(2))
        an_count = self.convert_byte_in_int(self.read_size(2))
        ns_count = self.convert_byte_in_int(self.read_size(2))
        ar_count = self.convert_byte_in_int(self.read_size(2))
        return Header(_id, flags, qd_count, an_count, ns_count, ar_count)

    def byte_in_bite(self, byte):
        in_bite = bin(self.convert_byte_in_int(byte))[2:]
        return ('0' * (8 - len(in_bite)) + in_bite)

    def add_next_parts_name_in_list(self, parts_name: list):
        while True:
            lenght_or_offset_part = self.read_size(1)

            if lenght_or_offset_part == b'\x00' or lenght_or_offset_part == b'':
                break

            in_bite_first_byte = self.byte_in_bite(lenght_or_offset_part)
            first_two_bite = in_bite_first_byte[0:2]

            if first_two_bite == "11":
                next_byte = self.read_size(1)
                next_pointer_str = in_bite_first_byte[2:] + self.byte_in_bite(next_byte)
                curr_pointer = self.offset_reader

                self.offset_reader = int(next_pointer_str, 2)
                self.add_next_parts_name_in_list(parts_name)
                self.offset_reader = curr_pointer
                break

            part_name = self.read_size(self.convert_byte_in_int(lenght_or_offset_part))
            parts_name.append(part_name)

    def read_name(self):
        parts_name = []
        self.add_next_parts_name_in_list(parts_name)
        name = ""
        for part in parts_name:
            name = name + part.decode() + "."
        return name

    def parse_question(self):
        name = self.read_name()
        _type = self.convert_byte_in_int(self.read_size(2))
        _class = self.read_size(2)
        self.index_end_question_query = self.offset_reader
        return Question(name, _type, _class)

    def parse_rr(self):
        name = self.read_name()
        _type = self.convert_byte_in_int(self.read_size(2))
        _class = self.read_size(2)
        ttl = self.convert_byte_in_int(self.read_size(4))
        lenght_data = self.convert_byte_in_int(self.read_size(2))
        rdata = self.read_size(lenght_data)
        return ResourceRecord(name, _type, _class, ttl, lenght_data, rdata)

