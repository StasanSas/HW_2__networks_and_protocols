import time
import socket
import select
from parser_bytes_in_class_dns import ParserBytes
from constructs_dns import *
import ipaddress



cache_dict = {}


def request_processing(request_from_client, not_parse_request, type_question):
    domain = str(request_from_client.question[0].name)
    start_server = "198.41.0.4"
    que = [start_server]
    socket_for_requests = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        id_server = que.pop(0)
        request = give_usual_query(not_parse_request)
        socket_for_requests.sendto(request, (id_server, 53))
        data, addr = socket_for_requests.recvfrom(1024)
        dns_response = ParserBytes(data).parse_byte_in_dns_message()
        for answer in dns_response.answer:
            if answer.type == type_question:
                expiration_time = time.time() + answer.ttl
                cache_dict[(domain, type_question)] = (data, expiration_time)
                return data
        for dns_parth_message in dns_response.authority, dns_response.additional:
            for rr in dns_parth_message:
                if rr.type == 1:
                    que.append(parse_byte_in_ipv4(rr.data))

def parse_byte_in_ipv4(bytes):
    result = ""
    for byte in bytes:
        result += str(byte)
        result += "."
    return result[:-1]


def processing_client_requests():
    main_socket_tcp_ipv4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    main_socket_tcp_ipv4.bind(('127.0.0.1', 53))
    main_socket_tcp_ipv4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    main_socket_tcp_ipv4.listen()


    main_socket_udp_ipv4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    main_socket_udp_ipv4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    main_socket_udp_ipv4.bind(('127.0.0.1', 53))


    sockets_for_read = [main_socket_tcp_ipv4, main_socket_udp_ipv4]
    while True:
        readable, _, _ = select.select(sockets_for_read, [], [])
        for sock in readable:
            if sock is main_socket_tcp_ipv4:
                client, addr = main_socket_tcp_ipv4.accept()
                data = client.recv(1024)
                main_socket_tcp_ipv4.sendto(process_search_id_with_cache(data), addr)
                client.close()

            elif sock is main_socket_udp_ipv4:
                data, addr = main_socket_udp_ipv4.recvfrom(1024)
                main_socket_udp_ipv4.sendto(process_search_id_with_cache(data), addr)

def process_search_id_with_cache(data):
    request_from_client = ParserBytes(data).parse_byte_in_dns_message()

    domain = str(request_from_client.question[0].name)
    type_qestion = (request_from_client.question[0].type)
    if (domain, type_qestion) not in cache_dict:
        message = request_processing(request_from_client, data, type_qestion)
    elif cache_dict[(domain, type_qestion)][1] < time.time():
        cache_dict.pop(domain)
        message = request_processing(request_from_client, data, type_qestion)
    else:
        message = data[0:2] + cache_dict[(domain, type_qestion)][0][2:]
    return message


processing_client_requests()














