import argparse
import sys
import socket
import threading
import queue
import random
import os

PROTOCOLS = {'NTP': b'NTP', 'DNS': b'DNS', 'SMTP': b'SMTP', 'POP3': b'POP3',
             'IMAP': b'IMAP', 'HTTP': b'HTTP'}
time = random.randint(2 ** 16, 2 ** 64 - 1).to_bytes(8, 'big')
UDP_CONST = b'\x13' + b'\0' * 39 + time

TCP = 't'
UDP = 'u'


class Scanner:
    def __init__(self, host: str, start_port: int = 1, end_port: int = 65535,
                 tcp: bool = True,
                 udp: bool = True, timeout: int = 0.5,
                 workers: int = os.cpu_count() - 1):
        self.host = host
        self.ports = make_queue(start_port, end_port, tcp, udp)
        socket.setdefaulttimeout(timeout)

        self.to_print = queue.Queue()
        self.isWorking = True

        self.threads = [threading.Thread(target=self.run) for _ in
                        range(workers)]

    def start(self):
        for t in self.threads:
            t.setDaemon(True)
            t.start()
        while not self.ports.empty() and self.isWorking:
            try:
                print(self.to_print.get(block=False))
            except queue.Empty:
                pass

        for t in self.threads:
            t.join()

        while not self.to_print.empty():
            print(self.to_print.get())

    def stop(self):
        self.isWorking = False
        for t in self.threads:
            t.join()

    def run(self):
        while self.isWorking:
            try:
                transport_protocol, port = self.ports.get(block=False)
            except queue.Empty:
                break
            else:
                if transport_protocol == TCP:
                    self.get_tcp(port)
                if transport_protocol == UDP:
                    self.get_udp(port)

    def get_tcp(self, port):
        sock = socket.socket()
        data_end = b'\r\n\r\n'
        try:
            sock.connect((self.host, port))
        except socket.error:
            pass
        except ConnectionResetError:
            pass
        except socket.timeout:
            pass
        else:
            sock.send(b'a' * 250 + data_end)
            data = sock.recv(1024)
            self.to_print.put(f'TCP {port}{define_protocol(data)}')
        finally:
            sock.close()

    def get_udp(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(UDP_CONST, (self.host, port))
            data, host = sock.recvfrom(1024)
        except ConnectionResetError:
            pass
        except socket.timeout:
            self.to_print.put('UDP {port}'.format(port=port))
        else:
            self.to_print.put('UDP {port}{define_protocol(data)}'
                              .format(port=port, data=data))
        finally:
            sock.close()


def make_queue(start_port, end_port, tcp, udp):
    q = queue.Queue()
    for i in range(start_port, end_port + 1):
        if tcp:
            q.put((TCP, i))
        if udp:
            q.put((UDP, i))
    return q


def define_protocol(data):
    data_length = len(data)
    if data_length > 4 and data[:4] == PROTOCOLS['HTTP']:
        return ' HTTP'

    if PROTOCOLS['SMTP'] in data:
        return ' SMTP'

    if PROTOCOLS['POP3'] in data:
        return ' POP3'

    if PROTOCOLS['IMAP'] in data:
        return ' IMAP'

    if data_length > 11 and data[:2] == UDP_CONST[:2] and (data[3] & 1) == 1:
        return ' DNS'

    if data_length > 39:
        mode = 7 & data[0]
        version = (data[0] >> 3) & 7

        if mode == 4 and version == 2 and time == data[24:32]:
            return ' NTP'

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

    scanner = Scanner(args.host, args.ports[0], args.ports[1],
                      args.tcp, args.udp, workers=os.cpu_count() - 1)
    try:
        scanner.start()
    except KeyboardInterrupt:
        scanner.stop()


if __name__ == "__main__":
    main(sys.argv)
