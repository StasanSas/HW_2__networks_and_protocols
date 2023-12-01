import time
from dnslib import DNSRecord, RR, A, DNSHeader, QTYPE
import socket
import select

cache_dict = {}


def ask_server_authority_servers_or_id(socket_for_requests, domain, id_server):
    request = DNSRecord.question(domain).pack()
    socket_for_requests.sendto(request, (id_server, 53))
    data, addr = socket_for_requests.recvfrom(1024)
    return DNSRecord.parse(data)

def give_answer_for_client(request_from_client, answer_for_client, domain):
    dns_response = DNSRecord(DNSHeader(id=request_from_client.header.id, qr=1, aa=1, ra=1), q=request_from_client.q)
    for rr in answer_for_client.rr:
        if rr.rtype == 1 or rr.rtype == 28:
            dns_response.add_answer(RR(domain, QTYPE.A, rdata=A(str(rr.rdata)), ttl=rr.ttl))
    return dns_response

def request_processing(request_from_client: DNSRecord):
    domain = str(request_from_client.q.qname)
    start_server = "198.41.0.4"
    que = [start_server]
    set_address = set()
    socket_for_requests = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        id_server = que.pop(0)
        answer_for_client = ask_server_authority_servers_or_id(socket_for_requests, domain, id_server)
        if len(answer_for_client.rr) != 0:
            return give_answer_for_client(request_from_client, answer_for_client, domain)
        authority_servers = answer_for_client.auth
        for data_about_server in authority_servers:
            server_name = str(data_about_server.rdata)
            ids_authority_servers = ask_server_authority_servers_or_id(socket_for_requests, server_name, "8.8.8.8")
            for rr in ids_authority_servers.rr:
                if (rr.rtype == 1 or rr.rtype == 28) and (str(rr.rdata) not in que) \
                        and (str(rr.rname) not in set_address):
                    que.append(str(rr.rdata))
                    set_address.add(str(rr.rname))

def processing_client_requests():
    main_socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    main_socket_tcp.bind(('127.0.0.1', 53))
    main_socket_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    main_socket_tcp.listen()

    main_socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    main_socket_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    main_socket_udp.bind(('127.0.0.1', 53))

    sockets_for_read = [main_socket_tcp, main_socket_udp]
    while True:
        readable, _, _ = select.select(sockets_for_read, [], [])
        for sock in readable:
            if sock is main_socket_tcp:
                client, addr = main_socket_tcp.accept()
                data = client.recv(1024)
                m = process_search_id_with_cache(data).pack()
                addr = tuple(addr)
                main_socket_tcp.sendto(m, (addr[0], addr[1]))
                client.close()

            elif sock is main_socket_udp:
                data, addr = main_socket_udp.recvfrom(1024)
                main_socket_udp.sendto(process_search_id_with_cache(data).pack(), addr)

def process_search_id_with_cache(data):
    request_from_client = DNSRecord.parse(data)

    domain = str(request_from_client.q.qname)
    if domain not in cache_dict:
        message = get_answer(request_from_client)
    else:
        ip_not_overdue = get_not_overdue_response(domain)
        if len(ip_not_overdue)==0:
            cache_dict.pop(domain)
            message = get_answer(request_from_client)
        else:
            message = get_message_from_not_overdue_cache(request_from_client, ip_not_overdue)
    return message

def get_message_from_not_overdue_cache(request_from_client, ip_not_overdue):
    domain = str(request_from_client.q.qname)
    message = DNSRecord(DNSHeader(id=request_from_client.header.id, qr=1, aa=1, ra=1), q=request_from_client.q)
    for ip_data in ip_not_overdue:
        t = ip_data[1] - (time.time() - cache_dict[domain][0])
        message.add_answer(RR(domain, QTYPE.A, rdata=A(ip_data[0]), ttl=int(t)))
        return message

def get_not_overdue_response(domain):
    ip_not_overdue = []
    for answer_ip in cache_dict[domain][1]:
        if time.time() - cache_dict[domain][0] < answer_ip[1]:
            ip_not_overdue.append(answer_ip)
    cache_dict[domain][1] = ip_not_overdue
    return ip_not_overdue

def get_answer(request_from_client):
    message = request_processing(request_from_client)
    domain = str(request_from_client.q.qname)
    cache_dict[domain] = [time.time(), get_list_answer(message)]
    return message

def get_list_answer(parsed_answer):
    l = []
    for rr in parsed_answer.rr:
        l.append([str(rr.rdata), rr.ttl])
    return l


processing_client_requests()














