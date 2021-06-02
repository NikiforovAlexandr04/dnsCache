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
            data = data.decode()
            type_r, name = data.split()
            time_now = time.time()
            in_cache = False
            for rec in self.cache:
                if rec['name'] == name and rec['type'] == type_r and time_now < rec['ttl']:
                    in_cache = True
                    sock.sendto(json.dumps(rec).encode('utf-8'), address)
                    break
            if not in_cache:
                self.send_message(data, sock_request, sock, address)

    def create_message(self, recording):
        type_rec = 0
        if recording.type == 2:
            type_rec = "NS"
        elif recording.type == 1:
            type_rec = "A"
        elif recording.type == 12:
            type_rec = "PTR"
        else:
            type_rec = "AAAA"
        message = {
            'name': recording.rrname.decode(),
            'type': type_rec,
            'ttl': recording.ttl,
            'current_ttl': time.time()
        }
        data = recording.rdata
        if type(data) is not str:
            data = data.decode()
        message['data'] = data
        return message

    def send_message(self, data, sock_request, sock, address):
        name, type_r = data.split()
        if type_r == "PTR":
            name = name.split('.')
            name = name[3] + '.' + name[2] + '.' + name[1] + '.' + name[0] + '.in-addr.arpa'
            print(name)
        dns = DNSQR(qname=name, qtype=type_r)
        message = DNS(qd=dns).build()
        sock_request.sendto(message, ("8.8.8.8", 53))
        response = sock_request.recv(2000)
        out = DNS(_pkt=response)
        rec = self.create_message(out.an)
        sock.sendto(json.dumps(rec).encode('utf-8'), address)
        self.cache_data(rec, out)

    def cache_data(self, rec, out):
        count = out.ancount - 1
        self.cache.append(rec)
        out = out.an
        for _ in range(count):
            rec = self.create_message(out.payload)
            self.cache.append(rec)
            out = out.payload
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
