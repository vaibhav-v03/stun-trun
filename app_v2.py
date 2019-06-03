#!/usr/bin/env python
# coding:utf-8

import socket
import struct
import random
import sys
import time
from threading import Thread
from collections import namedtuple


class stun_turn:
    def __init__(self, index, status, stun_port, turn_port):
        self.FullCone = "Full Cone"  # 0
        self.RestrictNAT = "Restrict NAT"  # 1
        self.RestrictPortNAT = "Restrict Port NAT"  # 2
        self.SymmetricNAT = "Symmetric NAT"  # 3
        self.UnknownNAT = "Unknown NAT"  # 4
        self.NATTYPE = (self.FullCone, self.RestrictNAT, self.RestrictPortNAT, self.SymmetricNAT, self.UnknownNAT)
        self.ip_addr = "54.165.124.138"
        self.turn_port = turn_port
        self.stun_port = stun_port
        self.index = index
        self.status = status
        self.stun()

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

    def turn(self, socket_turn, address_a, address_b, main_thread_pool, pool):
        symmetric_chat_clients = {}
        symmetric_chat_clients[address_a] = address_b
        symmetric_chat_clients[address_b] = address_a
        turn_forwarding = True
        error_msg_counter = 0
        while turn_forwarding:
            try:
                socket_turn.settimeout(30.0)
                data, addr = socket_turn.recvfrom(1024)
            except socket.timeout:
                print("turn socket timeout")
                socket_turn.close()
                if pool in main_thread_pool:
                    del main_thread_pool[pool]
                sys.exit()
            if data.startswith("LC Stop"):
                print("Terminate call request received, cleaning pool...")
                if address_a in symmetric_chat_clients:
                    del symmetric_chat_clients[address_a]
                if address_b in symmetric_chat_clients:
                    del symmetric_chat_clients[address_b]
                if pool in main_thread_pool:
                    del main_thread_pool[pool]
            else:
                # forward symmetric chat msg, act as TURN server
                try:
                    socket_turn.sendto(data, symmetric_chat_clients[addr])
                except KeyError:
                    if len(symmetric_chat_clients) != 0:
                        print("Someone else trying to join the talk, ignore...")
                        continue
                    socket_turn.sendto("LC Stop\0", addr)
                    print("Symmetric call ends, waiting for turn port timeout!")
                    error_msg_counter += 1
                    if error_msg_counter == 10:
                        print("Turn port time out, closing...")
                        socket_turn.close()
                        if pool in main_thread_pool:
                            del main_thread_pool[pool]
                        sys.exit()

    def stun(self):
        port = self.stun_port
        sockfd = None
        try:
            sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sockfd.bind(("", port))

            print "listening on *:%d (udp)\n" % port
            self.status[self.index] = True

            poolqueue = {}
            symmetric_chat_clients = {}

            ClientInfo = namedtuple("ClientInfo", "addr, nat_type_id")
            while True:
                data, addr = sockfd.recvfrom(1024)
                if data.startswith("del "):
                    print("Communication cancel requested!")
                    pool = data[4:]
                    if pool in poolqueue:
                        del poolqueue[pool]
                    if pool in symmetric_chat_clients:
                        print("Cancel request before connecting")
                        del symmetric_chat_clients[pool]
                    sockfd.sendto("cancel!!", addr)
                    print "Connection request canceled"
                    print "Continue listening on *:%d (udp)" % port
                else:
                    print "connection from %s:%d" % addr
                    try:
                        pool, nat_type_id, device_type = data.strip().split()
                    except:
                        print("pool info error %s" % data)
                        sockfd.sendto("cancel!!", addr)
                        continue

                    print "request received from {} for pool: {}".format(device_type, pool)

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
                            symmetric_chat_clients[pool] = [nat_type_id, addr, False]
                    else:
                        if pool in symmetric_chat_clients:
                            if nat_type_id != '0' or symmetric_chat_clients[pool][0] != '0':
                                # at least one is symmetric NAT
                                recorded_client_addr = symmetric_chat_clients[pool][1]
                                # prevent self connection
                                if recorded_client_addr == addr:
                                    continue

                                if not symmetric_chat_clients[pool][2]:
                                    socket_turn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                    socket_turn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                    turn_port_valid = True
                                    while turn_port_valid:
                                        print "turn server trying to connect to port *:%d (udp)" % self.turn_port
                                        try:
                                            socket_turn.bind(("", self.turn_port))
                                            turn_port_valid = False
                                        except socket.error:
                                            print "turn port is occupied at: %d" % self.turn_port
                                            self.turn_port = self.stun_port + random.randint(1, 999)
                                            continue
                                    print "listening on turn port *:%d (udp)" % self.turn_port
                                    sockfd.sendto(self.addr2bytes((self.ip_addr, self.turn_port), '0'),
                                                  recorded_client_addr)
                                    sockfd.sendto(self.addr2bytes((self.ip_addr, self.turn_port), '0'), addr)

                                    turn_thread = Thread(target=self.turn, args=(socket_turn, recorded_client_addr, addr, symmetric_chat_clients, pool))
                                    turn_thread.setDaemon(True)
                                    turn_thread.start()
                                    symmetric_chat_clients[pool] = ['0', (self.ip_addr, self.turn_port), True]
                                    print("Hurray! symmetric chat link established.")
                                    # del symmetric_chat_clients[pool]
                                    if pool in poolqueue:
                                        del poolqueue[pool]
                                else:
                                    print("retry request for the turn server from %s" % device_type)
                                    if device_type == '1':
                                        byte_sent = sockfd.sendto(self.addr2bytes(symmetric_chat_clients[pool][1], '0'), addr)
                                        print(byte_sent, len(self.addr2bytes(symmetric_chat_clients[pool][1], '0')))
                            else:
                                del symmetric_chat_clients[pool]  # neither clients are symmetric NAT
                        else:
                            symmetric_chat_clients[pool] = [nat_type_id, addr, False]
        except Exception as e:
            print("stun server on port %d is terminated, waiting for restart" % self.stun_port)
            print("Stun error: " + str(e))
            self.status[self.index] = False
            if sockfd is not None:
                sockfd.close()
            sys.exit()


if __name__ == "__main__":
    stun_ports = [7000, 8000, 9000, 10000, 11000, 12000, 13000]
    stun_status = [False, False, False, False, False, False, False]
    for i, stun_port in enumerate(stun_ports):
        stun_thread = Thread(target=stun_turn, args=(i, stun_status, stun_port, stun_port + 1))
        stun_thread.start()

    time.sleep(60)

    while True:
        for i, stun_port in enumerate(stun_ports):
            if not stun_status[i]:
                print("status on port %d fails, restarting...." % stun_ports[i], stun_status[i])
                stun_thread = Thread(target=stun_turn, args=(i, stun_status, stun_ports[i], stun_ports[i] + 1))
                stun_thread.start()
        time.sleep(60)
