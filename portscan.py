import argparse
import sys
import socket
import threading
import queue
import random
import os

time = random.randint(2 ** 16, 2 ** 64 - 1).to_bytes(8, 'big')
UDP_CONST = b'\x13' + b'\0' * 39 + time


class Scanner:
    def __init__(self, host: str, ports, tcp: bool = True, udp: bool = True,
                 timeout: int = 1, workers: int = os.cpu_count() - 1):
        self.host = host
        self.ports = _make_queue(ports, tcp, udp)
        self.to_print = queue.Queue()
        self.threads = [threading.Thread(target=self.run, daemon=True)
                        for _ in range(workers)]
        socket.setdefaulttimeout(timeout)

    def start(self):
        for t in self.threads:
            t.start()
        while self.ports.qsize() > 0:
            try:
                print(self.to_print.get(block=False))
            except queue.Empty:
                pass
        for t in self.threads:
            t.join()
        while not self.to_print.qsize() == 0:
            print(self.to_print.get())

    def run(self):
        try:
            while True:
                conn_type, port = self.ports.get(block=False)
                if conn_type == 'tcp':
                    self._get_tcp(port)
                elif conn_type == 'udp':
                    self._get_udp(port)
        except queue.Empty:
            return

    def _get_tcp(self, port):
        serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect = serv_sock.connect_ex((self.host, port))
        data_end = b'\r\n\r\n'
        if not connect:
            try:
                sock = socket.socket()
                sock.connect((self.host, port))
                sock.send(b'a' * 250 + data_end)
                data = sock.recv(1024)
                self.to_print.put(f'TCP {port} {define_protocol(data)}')
                sock.close()
            except Exception:
                self.to_print.put(f'TCP {port}')

        serv_sock.close()

    def _get_udp(self, port):
        serv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        connect = serv_sock.connect_ex((self.host, port))
        if not connect:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(UDP_CONST, (self.host, port))
                data, host = sock.recvfrom(1024)
                self.to_print.put(f'UDP {port} {define_protocol(data)}')
                sock.close()
            except ConnectionRefusedError:
                pass
            except socket.timeout:
                pass
            # self.to_print.put(f'UDP {port}')
        serv_sock.close()


def _make_queue(port_pool, tcp, udp):
    q = queue.Queue()
    [q.put(i) for i in
     [('tcp', x) for x in port_pool if tcp] + [('udp', x) for x in port_pool if
                                               udp]]
    return q


def define_protocol(data):
    data_length = len(data)
    if data_length > 4 and data[:4] == b'HTTP':
        return 'HTTP'
    if b'SMTP' in data:
        return 'SMTP'
    if b'POP3' in data:
        return 'POP3'
    if b'IMAP' in data:
        return 'IMAP'
    if (data_length > 11 and data[:2] == UDP_CONST[:2] and
            data[3] & 1 == 1):
        return 'DNS'
    if data_length > 39:
        if (7 & data[0] == 4 and
                (data[0] >> 3) & 7 == 2 and time == data[24:32]):
            return 'NTP'
    return ''


def arg_parse(args):
    parser = argparse.ArgumentParser(
        description="Сканер TCP и UDP портов удалённого компьютера")

    parser.add_argument('-t', dest='tcp', action='store_true',
                        help='Сканировать tcp.'
                             'Если протокол не распознан,,'
                             'то пишется только TCP/UDP и номер порта.')
    parser.add_argument('-u', dest='udp', action='store_true',
                        help='Сканировать udp.')
    parser.add_argument('-p', '--ports', action='store', nargs=2, type=int,
                        default=[1, 65535], help='Диапазон портов для скана'
                                                 'По умолчанию: все порты')
    parser.add_argument('host', action='store', help='Хост для сканирования')

    args = parser.parse_args(args)

    if not args.tcp and not args.udp:
        args.tcp = True

    return args


def main(args):
    args = arg_parse(args[1:])

    scanner = Scanner(args.host, range(args.ports[0], args.ports[1] + 1),
                      args.tcp, args.udp, workers=os.cpu_count() - 1)
    try:
        scanner.start()
    except KeyboardInterrupt:
        sys.exit(-1)


if __name__ == "__main__":
    main(sys.argv)
