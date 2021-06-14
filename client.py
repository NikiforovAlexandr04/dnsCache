import json
import socket
from scapy.layers.dns import *


def get_type(type):
    if type == 2:
        type_rec = "NS"
    elif type == 1:
        type_rec = "A"
    elif type == 12:
        type_rec = "PTR"
    else:
        type_rec = "AAAA"
    return type_rec


if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns = DNSQR(qname='google.com'.encode(), qtype='A')
    message = DNS(qd=dns).build()
    sock.sendto(message, ('127.0.0.1', 53))
    answer, address = sock.recvfrom(2000)
    package = DNS(_pkt=answer)
    print("name: " + package.qd.qname.decode())
    print("type: " + get_type(package.qd.qtype))
    print("answer: " + package.payload.load[:len(package.payload)].decode())
    if package.ns is not None:
        print("authority: " + package.fields['ns'])
    if package.ar is not None:
        print("addition: " + package.fields['ar'])
