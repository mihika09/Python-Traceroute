import socket
import struct
import os
import time
import sys
import select
import argparse

ICMP_ECHO = 8
ICMP_ECHO_REPLY = 0
ICMP_TIME_EXCEEDED = 11
MIN_SLEEP = 1000

if sys.platform.startswith('win32'):
    timer = time.clock
else:
    timer = time.time


def calculate_checksum(packet):
    countTo = (len(packet) // 2) * 2

    count = 0
    sum = 0

    while count < countTo:
        if sys.byteorder == "little":
            loByte = packet[count]
            hiByte = packet[count + 1]
        else:
            loByte = packet[count + 1]
            hiByte = packet[count]
        sum = sum + (hiByte * 256 + loByte)
        count += 2

    if countTo < len(packet):
        sum += packet[count]

        # sum &= 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)  # adding the higher order 16 bits and lower order 16 bits
    sum += (sum >> 16)
    answer = ~sum & 0xffff
    answer = socket.htons(answer)

    return answer


def is_valid_ip(hostname):
    ip_parts = hostname.strip().split('.')
    if len(ip_parts) != 4:
        return False

    for part in ip_parts:
        try:
            if int(part) < 0 or int(part) > 255:
                return False
        except ValueError:
            return False

    return True


def to_ip(hostname):
    if is_valid_ip(hostname):
        return hostname
    return socket.gethostbyname(hostname)


class Traceroute:
    def __init__(self, destination_server, count_of_packets, packet_size, max_hops, timeout):
        self.destination_server = destination_server
        self.count_of_packets = count_of_packets
        self.packet_size = packet_size
        self.max_hops = max_hops
        self.timeout = timeout
        self.identifier = os.getpid() & 0xffff
        self.seq_no = 0
        self.delays = []
        self.prev_sender_hostname = ""

        self.ttl = 1
        try:
            self.destination_ip = to_ip(destination_server)
        except socket.gaierror:
            self.print_unknownhost()

    def print_start(self):
        print("traceroute to {} ({}), {} hops max, {} byte packets".format(self.destination_server, self.destination_ip,
                                                                           self.max_hops, self.packet_size))

    def print_unknownhost(self):
        print("traceroute: unknown host {}".format(self.destination_server))

    def print_timeout(self):
        if self.seq_no == 1:
            if self.ttl < 10:
                print(" {}  ".format(self.ttl), end="")
            else:
                print("{}  ".format(self.ttl), end="")
        print("* ", end="")
        if self.seq_no == self.count_of_packets:
            print()

    def print_trace(self, delay, ip_header):

        ip = socket.inet_ntoa(struct.pack('!I', ip_header['Source_IP']))
        try:
            sender_hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            sender_hostname = ip

        if self.prev_sender_hostname != sender_hostname:
            if self.ttl < 10:
                print(" {}  {} ({}) {:.3f}ms ".format(self.ttl, sender_hostname, ip, delay), end="")
            else:
                print("{}  {} ({}) {:.3f}ms ".format(self.ttl, sender_hostname, ip, delay), end="")
            self.prev_sender_hostname = sender_hostname

        else:
            print("{:.3f} ms ".format(delay), end="")

        if self.seq_no == self.count_of_packets:
            print()
            self.prev_sender_hostname = ""
            if MIN_SLEEP > delay:
                time.sleep((MIN_SLEEP - delay) / 1000)

    def header_to_dict(self, keys, packet, struct_format):
        values = struct.unpack(struct_format, packet)
        return dict(zip(keys, values))

    def start_traceroute(self):

        icmp_header = None
        while self.ttl <= self.max_hops:
            self.seq_no = 0
            try:
                for i in range(self.count_of_packets):
                    icmp_header = self.tracer()

            except KeyboardInterrupt:  # handles Ctrl+C
                break

            self.ttl += 1
            if icmp_header is not None:
                if icmp_header['type'] == ICMP_ECHO_REPLY:
                    break

    def tracer(self):

        try:
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("ICMP"))
            icmp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)

        except socket.error as err:
            if err.errno == 1:
                print("Operation not permitted: ICMP messages can only be sent from a process running as root")
            else:
                print("Error: {}".format(err))

            sys.exit()

        self.seq_no += 1
        if self.ttl == 1 and self.seq_no == 1:
            self.print_start()

        sent_time = self.send_icmp_echo(icmp_socket)

        if sent_time is None:
            return

        receive_time, icmp_header, ip_header = self.receive_icmp_reply(icmp_socket)

        icmp_socket.close()
        if receive_time:
            delay = (receive_time - sent_time) * 1000.0
            self.print_trace(delay, ip_header)

        return icmp_header

    def send_icmp_echo(self, icmp_socket):

        header = struct.pack("!BBHHH", ICMP_ECHO, 0, 0, self.identifier, self.seq_no)

        start_value = 65
        payload = []
        for i in range(start_value, start_value+self.packet_size):
            payload.append(i & 0xff)

        data = bytes(payload)
        checksum = calculate_checksum(header + data)
        header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum, self.identifier, self.seq_no)

        packet = header + data

        send_time = timer()
        try:
            icmp_socket.sendto(packet, (self.destination_server, 1))

        except socket.error as err:
            print("General error: %s", err)
            icmp_socket.close()
            return

        return send_time

    def receive_icmp_reply(self, icmp_socket):

        timeout = self.timeout / 1000

        while True:
            # started_select = time.time()
            inputReady, _, _ = select.select([icmp_socket], [], [], timeout)
            # how_long_in_select = time.time() - started_select
            receive_time = timer()

            if not inputReady:  # timeout
                self.print_timeout()
                return None, None, None

            packet_data, address = icmp_socket.recvfrom(2048)

            icmp_keys = ['type', 'code', 'checksum', 'identifier', 'sequence number']
            icmp_header = self.header_to_dict(icmp_keys, packet_data[20:28], "!BBHHH")

            # if icmp_header['type'] == 11:  # time exceeded

            ip_keys = ['VersionIHL', 'Type_of_Service', 'Total_Length', 'Identification', 'Flags_FragOffset', 'TTL',
                       'Protocol', 'Header_Checksum', 'Source_IP', 'Destination_IP']

            ip_header = self.header_to_dict(ip_keys, packet_data[:20], "!BBHHHBBHII")

            return receive_time, icmp_header, ip_header


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('destination_server')
    parser.add_argument('-c', '--count', required=False, nargs='?', default=3, type=int, metavar='Count of packets')
    parser.add_argument('-t', '--timeout', required=False, nargs='?', default=1000, type=int, metavar='Timeout in ms')
    parser.add_argument('-m', '--maxhops', required=False, nargs='?', default=64, type=int, metavar='Max hops')
    parser.add_argument('-p', '--packet_size', required=False, nargs='?', default=55, type=int,
                        metavar='Packet size in bytes')

    return parser


def traceroute(destination_server, count_of_packets=3, packet_size=52, max_hops=64, timeout=1000):
    t = Traceroute(destination_server, count_of_packets, packet_size, max_hops, timeout)
    t.start_traceroute()


if __name__ == '__main__':
    parser = create_parser()
    args = parser.parse_args(sys.argv[1:])
    destination_server = args.destination_server
    timeout = args.timeout
    packet_size = args.packet_size
    count = args.count
    max_hops = args.maxhops
    traceroute(destination_server, count, packet_size, max_hops, timeout)
