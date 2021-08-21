import json
import socket
from json import JSONDecodeError
import base64

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
            for recording in self.cache:
                if name.decode() in recording:
                    rec = recording[name.decode()]
                    if rec[0] == type_r:
                        in_cache = True
                        packet.fields['ancount'] = rec[1]
                        packet.fields['an'] = DNSRR(rrname=name, type=rec[0], rdata=rec[2])
                        sock.sendto(packet.build(), address)
            if not in_cache:
                self.send_message(name, type_r, sock_request, sock, address, packet)

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

    def send_message(self, name, type_r, sock_request, sock, address, data):
        name = name.decode()
        if type_r == "PTR":
            name = name.split('.')
            name = name[3] + '.' + name[2] + '.' + name[1] + '.' + name[0] + '.in-addr.arpa'
        qd = DNSQR(qname=name.encode(), qtype=type_r)
        data.fields['qd'] = qd
        sock_request.sendto(data.build(), ("8.8.8.8", 53))
        response = sock_request.recv(2000)
        out = DNS(_pkt=response)
        print(out.fields)
        data.fields['an'] = out.fields['an']
        data.fields['ancount'] = out.fields['ancount']
        sock.sendto(data.build(), address)
        self.cache_data(out, name, type_r)

    def cache_data(self, recording, name, type):
        an = recording.fields['an']
        ns = recording.fields['ns']
        ar = recording.fields['ar']
        if an is not None:
            if type == 'PTR':
                self.cache.append({name: ['A', recording.fields['ancount'], an.rdata.decode(), an.ttl, time.time()]})
            else:
                self.cache.append({name: ['A', recording.fields['ancount'], an.rdata, an.ttl, time.time()]})
        if ns is not None:
            try:
                self.cache.append({name: ['NS', recording.fields['nscount'], ns.rdata, an.ttl, time.time()]})
            except AttributeError:
                pass
        if ar is not None:
            self.cache.append({name: ['AAAA', recording.fields['arcount'], ar.rdata]})
        with open("cache.json", mode="w") as file:
            file.write(json.dumps(self.cache))


def read_cache():
    cache = []
    try:
        with open('cache.json', mode='r') as file:
            file = json.load(file)
            for rec in file:
                for key in rec:
                    if rec[key][3] + rec[key][4] < time.time():
                        cache.append(rec)
    except JSONDecodeError:
        pass
    dns = Server(cache)
    dns.start_server()


if __name__ == '__main__':
    read_cache()
