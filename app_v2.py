#!/usr/bin/env python
# coding:utf-8

import socket
import struct
import random
import sys
from threading import Thread
from collections import namedtuple

class stun_turn:
    def __init__(self):
        self.FullCone = "Full Cone"  # 0
        self.RestrictNAT = "Restrict NAT"  # 1
        self.RestrictPortNAT = "Restrict Port NAT"  # 2
        self.SymmetricNAT = "Symmetric NAT"  # 3
        self.UnknownNAT = "Unknown NAT"  # 4
        self.NATTYPE = (self.FullCone, self.RestrictNAT, self.RestrictPortNAT, self.SymmetricNAT, self.UnknownNAT)
        self.ip_addr = "3.80.165.3"
        self.stun_port = 7000

    def addr2bytes(self, addr, nat_type_id):
        """Convert an address pair to a hash."""
        host, port = addr
        try:
            host = socket.gethostbyname(host)
        except (socket.gaierror, socket.error):
            raise ValueError("invalid host")
        try:
            port = int(port)
        except ValueError:
            raise ValueError("invalid port")
        try:
            nat_type_id = int(nat_type_id)
        except ValueError:
            raise ValueError("invalid NAT type")
        bytes = socket.inet_aton(host)
        bytes += struct.pack("H", port)
        bytes += struct.pack("H", nat_type_id)
        return bytes

    def turn(self, socket_turn, address_a, address_b):
        symmetric_chat_clients = {}
        symmetric_chat_clients[address_a] = address_b
        symmetric_chat_clients[address_b] = address_a
        turn_forwarding = True
        while turn_forwarding:
            data, addr = socket_turn.recvfrom(1024)
            if data.startswith("msg "):
                # forward symmetric chat msg, act as TURN server
                try:
                    socket_turn.sendto(data[4:], symmetric_chat_clients[addr])
                    # print("msg successfully forwarded to {0}".format(symmetric_chat_clients[addr]))
                    # print(data[4:])
                except KeyError:
                    socket_turn.sendto("LC Stop\0", addr)
                    print("something is wrong with symmetric_chat_clients!")
                    turn_forwarding = False

    def stun(self, stun_port):
        self.stun_port = stun_port
        try:
            port = int(self.stun_port)
        except (IndexError, ValueError):
            pass

        sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sockfd.bind(("", port))
        print "listening on *:%d (udp)" % port

        poolqueue = {}

        # A,B with addr_A,addr_B,pool=100
        # temp state {100:(nat_type_id, addr_A, addr_B)}
        # final state {addr_A:addr_B, addr_B:addr_A}
        symmetric_chat_clients = {}

        ClientInfo = namedtuple("ClientInfo", "addr, nat_type_id")
        while True:
            data, addr = sockfd.recvfrom(1024)
            print "connection from %s:%d" % addr
            try:
                pool, nat_type_id = data.strip().split()
            except:
                continue
            sockfd.sendto("ok {0}".format(pool), addr)
            print("pool={0}, nat_type={1}, ok sent to client".format(pool, self.NATTYPE[int(nat_type_id)]))
            data, addr = sockfd.recvfrom(2)
            if data != "ok":
                print("Didn't get ok back from client, actual msg is: " + data)
                print("Cleaning the pool...")
                continue

            print "request received for pool:", pool

            if nat_type_id == '0':
                try:
                    a, b = poolqueue[pool].addr, addr
                    nat_type_id_a, nat_type_id_b = poolqueue[pool].nat_type_id, nat_type_id
                    sockfd.sendto(self.addr2bytes(a, nat_type_id_a), b)
                    sockfd.sendto(self.addr2bytes(b, nat_type_id_b), a)
                    print "linked", pool
                    del poolqueue[pool]
                # KeyError ==> pool not exist yet, initiate one
                except KeyError:
                    poolqueue[pool] = ClientInfo(addr, nat_type_id)
            else:
                if pool in symmetric_chat_clients:
                    if nat_type_id != '0' or symmetric_chat_clients[pool][0] != '0':
                        # at least one is symmetric NAT
                        recorded_client_addr = symmetric_chat_clients[pool][1]

                        socket_turn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        turn_port_valid = True
                        while turn_port_valid:
                            turn_port = random.randint(7001, 8000)
                            print "turn server trying to connect to port *:%d (udp)" % turn_port
                            try:
                                socket_turn.bind(("", turn_port))
                                turn_port_valid = False
                            except:
                                continue
                        print "listening on turn port *:%d (udp)" % turn_port
                        sockfd.sendto(self.addr2bytes((self.ip_addr, turn_port), '0'), recorded_client_addr)
                        sockfd.sendto(self.addr2bytes((self.ip_addr, turn_port), '0'), addr)

                        turn_thread = Thread(target=self.turn(socket_turn, recorded_client_addr, addr))
                        turn_thread.start()
                        print("Hurray! symmetric chat link established.")
                        del symmetric_chat_clients[pool]
                        del poolqueue[pool]
                    else:
                        del symmetric_chat_clients[pool]  # neither clients are symmetric NAT
                else:
                    symmetric_chat_clients[pool] = (nat_type_id, addr)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: app.py port")
        exit(0)
    else:
        assert sys.argv[1].isdigit(), "port should be a number!"
        app = stun_turn()
        app.stun(sys.argv[1])
