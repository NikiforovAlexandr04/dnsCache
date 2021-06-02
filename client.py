import json
import socket


class Client:
    def start_send(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while True:
            user_request = input()
            sock.sendto(user_request.encode(), ('127.0.0.1', 53))
            request = sock.recv(2000)
            response = json.loads(request)
            print('name: ' + response['name'] + '  type: ' + response['type'] + '  TTL: ' + str(response['ttl'])
                  + '  data: ' + str(response['data']))


if __name__ == '__main__':
    client = Client()
    client.start_send()
