import json
import socket
from json import JSONDecodeError

from scapy.layers.dns import *


class Server:
    def __init__(self, cache):
        self.cache = cache

    def start_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 53))
        sock_request = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while True:
            data, address = sock.recvfrom(2000)
            packet = DNS(_pkt=data)
            type_r = packet.fields['qd'].qtype
            name = packet.fields['qd'].qname
            type_r = self.get_type(type_r)
            in_cache = False
            for rec in self.cache:
                if rec['name'] == name.decode() and rec['type'] == type_r:
                    in_cache = True
                    message = self.build_message(rec)
                    sock.sendto(message, address)
                    break
            if not in_cache:
                self.send_message(name, type_r, sock_request, sock, address, data)

    def get_type(self, type):
        if type == 2:
            type_rec = "NS"
        elif type == 1:
            type_rec = "A"
        elif type == 12:
            type_rec = "PTR"
        else:
            type_rec = "AAAA"
        return type_rec

    def create_message(self, recording):
        type_rec = self.get_type(recording.an.type)
        message = {
            'name': recording.an.rrname.decode(),
            'type': type_rec,
            'ttl': recording.an.ttl,
            'current_ttl': time.time()
        }
        an = recording.an.rdata
        message['an'] = an
        ns = recording.ns
        message['ns'] = ns
        ar = recording.ar
        message['ar'] = ar
        return message

    def build_message(self, message):
        build_message = DNSQR(qname=message['name'], qtype=message['type'])
        mes = DNS(qd=build_message, an=message['an'], ns=message['ns'], ar=message['ar'])
        return mes.build()

    def send_message(self, name, type_r, sock_request, sock, address, data):
        if type_r == "PTR":
            name = name.split('.')
            name = name[3] + '.' + name[2] + '.' + name[1] + '.' + name[0] + '.in-addr.arpa'
        dns = DNSQR(qname=name, qtype=type_r)
        message = DNS(qd=dns)
        sock_request.sendto(message.build(), ("8.8.8.8", 53))
        response = sock_request.recv(2000)
        out = DNS(_pkt=response)
        rec = self.create_message(out)

        message = self.build_message(rec)
        sock.sendto(message, address)
        self.cache_data(rec)

    def cache_data(self, rec):
        self.cache.append(rec)
        with open("cache.json", mode="w") as file:
            file.write(json.dumps(self.cache))


def read_cache():
    cache = []
    try:
        with open('cache.json', mode='r') as file:
            file = json.load(file)
            for rec in file:
                if rec['ttl'] + rec['current_ttl'] < time.time():
                    cache.append(rec)
    except JSONDecodeError:
        pass
    dns = Server(cache)
    dns.start_server()


if __name__ == '__main__':
    read_cache()
