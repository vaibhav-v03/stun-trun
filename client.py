#!/usr/bin/env python
# coding:utf-8

import optparse
import socket
import struct
import sys
import time
import pyaudio
import audioop
from threading import Event, Thread

import stun

FullCone = "Full Cone"  # 0
RestrictNAT = "Restrict NAT"  # 1
RestrictPortNAT = "Restrict Port NAT"  # 2
SymmetricNAT = "Symmetric NAT"  # 3
UnknownNAT = "Unknown NAT"  # 4
NATTYPE = (FullCone, RestrictNAT, RestrictPortNAT, SymmetricNAT, UnknownNAT)


def bytes2addr(bytes):
    """Convert a hash to an address pair."""
    if len(bytes) != 8:
        raise ValueError("invalid bytes")
    host = socket.inet_ntoa(bytes[:4])
    port = struct.unpack("H", bytes[-4:-2])[0]  # unpack returns a tuple even if it contains exactly one item
    nat_type_id = struct.unpack("H", bytes[-2:])[0]
    target = (host, port)
    return target, nat_type_id


class Client():
    def __init__(self):
        # initialize the audio object
        p = pyaudio.PyAudio()
        self.in_stream = p.open(format=pyaudio.paInt16,
                           channels=1,
                           rate=16000,
                           output=True)

        self.CHUNK = 512
        self.out_stream = p.open(format=pyaudio.paInt16,
                            channels=1,
                            rate=16000,
                            input=True,
                            frames_per_buffer=self.CHUNK)
        try:
            master_ip = '127.0.0.1' if sys.argv[1] == 'localhost' else sys.argv[1]
            self.master = (master_ip, int(sys.argv[2]))
            self.pool = sys.argv[3].strip()
            self.sockfd = self.target = None
            self.periodic_running = False
            self.peer_nat_type = None
        except (IndexError, ValueError):
            print(sys.stderr, "usage: %s <host> <port> <pool>" % sys.argv[0])
            sys.exit(65)

    def request_for_connection(self, nat_type_id=0):
        self.sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sockfd.sendto(self.pool + ' {0} {1}'.format(nat_type_id, '1'), self.master)
        # data, addr = self.sockfd.recvfrom(len(self.pool) + 3)
        # if data != "ok " + self.pool:
        #     print(sys.stderr, "unable to request!")
        #     sys.exit(1)
        # self.sockfd.sendto("ok", self.master)
        sys.stderr = sys.stdout
        print(sys.stderr,
              "request sent, waiting for partner in pool '%s'..." % self.pool)
        data, addr = self.sockfd.recvfrom(8)

        self.target, peer_nat_type_id = bytes2addr(data)
        print(self.target, peer_nat_type_id)
        self.peer_nat_type = NATTYPE[peer_nat_type_id]
        print(sys.stderr, "connected to {1}:{2}, its NAT type is {0}".format(
            self.peer_nat_type, *self.target))

    def recv_msg(self, sock, is_restrict=False, event_r=None):
        if is_restrict:
            while True:
                data, addr = sock.recvfrom(1024)
                if self.periodic_running:
                    print("periodic_send is alive")
                    self.periodic_running = False
                    event_r.set()
                    print("received msg from target,"
                          "periodic send cancelled, chat start.")
                if addr == self.target or addr == self.master:
                    sys.stdout.write(data)
                    if data == "punching...\n":
                        sock.sendto("end punching\n", addr)
        else:
            while True:
                data, addr = sock.recvfrom(1024)  # received peer's ip + port from server
                if addr == self.target or addr == self.master:
                    # sys.stdout.write(data)
                    data = audioop.ulaw2lin(data, 2)
                    self.in_stream.write(data)
                    if data == "punching...\n":  # peer是restrict
                        sock.sendto("end punching", addr)

    def send_msg(self, sock):
        while True:
            # data = sys.stdin.readline()
            data = audioop.lin2ulaw(self.out_stream.read(self.CHUNK), 2)
            sock.sendto(data, self.target)

    @staticmethod
    def start_working_threads(send, recv, event=None, *args, **kwargs):
        ts = Thread(target=send, args=args)
        ts.setDaemon(True)
        ts.start()
        if event:
            event.wait()
        tr = Thread(target=recv, args=args, kwargs=kwargs)
        tr.setDaemon(True)
        tr.start()

    def chat_fullcone(self):
        self.start_working_threads(self.send_msg, self.recv_msg, None,
                                   self.sockfd)

    def chat_restrict(self):
        from threading import Timer
        cancel_event = Event()

        def send(count):
            self.sockfd.sendto('punching...\n', self.target)
            print("UDP punching package {0} sent".format(count))
            if self.periodic_running:
                Timer(0.5, send, args=(count + 1,)).start()

        self.periodic_running = True
        send(0)
        kwargs = {'is_restrict': True, 'event_r': cancel_event}
        self.start_working_threads(self.send_msg, self.recv_msg, None,
                                   self.sockfd, **kwargs)

    def chat_symmetric(self):
        """
        Completely rely on relay server(TURN)
        """
        def send_msg_symm(sock):
            while True:
                # data = 'msg ' + sys.stdin.readline()
                data = 'msg '
                data += audioop.lin2ulaw(self.out_stream.read(self.CHUNK), 1)
                sock.sendto(data, self.master)

        def recv_msg_symm(sock):

            while True:
                data, addr = sock.recvfrom(1024)
                if addr == self.master:
                    # sys.stdout.write(data)
                    data = audioop.ulaw2lin(data, 2)
                    self.in_stream.write(data)

        self.start_working_threads(send_msg_symm, recv_msg_symm, None,
                                   self.sockfd)

    def main(self, test_nat_type=None):
        """
        nat_type is the nat type of self
        peer_nat_type the peer's nat type obtained from the server
        the chat mode is depend on the nat type: e.g. self's NAT type is restrict, then I have to keep sending packets
        to peer, so that my NAT device can recognize peer's address as 'address I sent packets'. Until I get back from
        peer, the period sending will be terminated
        """
        if not test_nat_type:
            nat_type, _, _ = self.get_nat_type()
        else:
            nat_type = test_nat_type  # NAT type from the argv, then just use it rather than request the nat type
        try:
            self.request_for_connection(nat_type_id=NATTYPE.index(nat_type))
        except ValueError:
            print("NAT type is %s" % nat_type)
            self.request_for_connection(nat_type_id=4)  # Unknown NAT

        if nat_type == UnknownNAT or self.peer_nat_type == UnknownNAT:
            print("Symmetric chat mode")
            self.chat_symmetric()
        if nat_type == SymmetricNAT or self.peer_nat_type == SymmetricNAT:
            # print("Symmetric chat mode")
            # self.chat_symmetric()
            print("FullCone chat mode")
            self.chat_fullcone()
        elif nat_type == FullCone:
            print("FullCone chat mode")
            self.chat_fullcone()
        elif nat_type in (RestrictNAT, RestrictPortNAT):
            print("Restrict chat mode")
            self.chat_restrict()
        else:
            print("NAT type wrong!")

        while True:
            try:
                time.sleep(0.5)
            except KeyboardInterrupt:
                print("exit")
                sys.exit(0)

    @staticmethod
    def get_nat_type():
        parser = optparse.OptionParser(version=stun.__version__)
        parser.add_option(
            "-d",
            "--debug",
            dest="DEBUG",
            action="store_true",
            default=False,
            help="Enable debug logging")
        parser.add_option(
            "-H",
            "--host",
            dest="stun_host",
            default=None,
            help="STUN host to use")
        parser.add_option(
            "-P",
            "--host-port",
            dest="stun_port",
            type="int",
            default=3478,
            help="STUN host port to use (default: "
            "3478)")
        parser.add_option(
            "-i",
            "--interface",
            dest="source_ip",
            default="0.0.0.0",
            help="network interface for client (default: 0.0.0.0)")
        parser.add_option(
            "-p",
            "--port",
            dest="source_port",
            type="int",
            default=54320,
            help="port to listen on for client "
            "(default: 54320)")
        (options, args) = parser.parse_args()
        if options.DEBUG:
            stun.enable_logging()
        kwargs = dict(
            source_ip=options.source_ip,
            source_port=int(options.source_port),
            stun_host=options.stun_host,
            stun_port=options.stun_port)
        nat_type, external_ip, external_port = stun.get_ip_info(**kwargs)
        print("NAT Type:", nat_type)
        print("External IP:", external_ip)
        print("External Port:", external_port)
        return nat_type, external_ip, external_port


if __name__ == "__main__":
    c = Client()
    try:
        test_nat_type = NATTYPE[int(sys.argv[4])]  # input the number 0,1,2,3
    except IndexError:
        test_nat_type = None

    c.main(test_nat_type)
