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
    def __init__(self, index, status, stun_port, turn_port, full_cone_pool, symmetric_pool):
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
        self.turn_id = 0
        self.status = status
        self.poolqueue = full_cone_pool
        self.symmetric_chat_clients = symmetric_pool
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

    def turn(self, socket_turn, address_a, address_b, main_thread_pool, pool, stun_id, turn_id):
        inner_symmetric_chat_clients = {}
        inner_symmetric_chat_clients[address_a] = address_b
        inner_symmetric_chat_clients[address_b] = address_a
        print("stun id {} -- turn id {}".format(stun_id, turn_id))
        print(inner_symmetric_chat_clients)
        print("====== turn server start ======")
        turn_forwarding = True
        error_msg_counter = 0
        other_msg_counter = 0
        while turn_forwarding:
            try:
                socket_turn.settimeout(5.0)
                data, addr = socket_turn.recvfrom(1024)
            except socket.timeout:
                socket_turn.close()
                if pool in main_thread_pool and main_thread_pool[pool][2]:
                    del main_thread_pool[pool]
                print("stun id {} -- turn id {} socket timeout".format(stun_id, turn_id))
                print("===================")
                sys.exit()
            if data.startswith("LC Stop"):
                print("Terminate call request received, cleaning pool...")
                inner_symmetric_chat_clients.clear()
                if pool in main_thread_pool:
                    del main_thread_pool[pool]
            else:
                # forward symmetric chat msg, act as TURN server
                try:
                    socket_turn.sendto(data, inner_symmetric_chat_clients[addr])
                except KeyError:
                    if len(inner_symmetric_chat_clients) != 0:
                        print("{} trying to join the talk".format(addr))
                        if addr[0] == address_a[0]:
                            inner_symmetric_chat_clients[addr] = address_b
                            inner_symmetric_chat_clients[address_b] = addr
                        elif addr[0] == address_b[0]:
                            inner_symmetric_chat_clients[addr] = address_a
                            inner_symmetric_chat_clients[address_a] = addr
                        else:
                            if pool in main_thread_pool:
                                del main_thread_pool[pool]
                            other_msg_counter += 1
                            if other_msg_counter >= 20:
                                socket_turn.close()
                                sys.exit()
                        print("updated pool info: ".format(inner_symmetric_chat_clients))
                        continue
                    socket_turn.sendto("LC Stop\0", addr)
                    if pool in main_thread_pool:
                        del main_thread_pool[pool]
                    print("Symmetric call ends, waiting for turn port timeout!")
                    error_msg_counter += 1
                    if error_msg_counter == 10:
                        print("Turn port time out, closing...")
                        socket_turn.close()
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

            ClientInfo = namedtuple("ClientInfo", "addr, nat_type_id")
            while True:
                data, addr = sockfd.recvfrom(1024)
                if data.startswith("del "):
                    print("Communication cancel requested!")
                    pool = data[4:]
                    if pool in self.poolqueue:
                        del self.poolqueue[pool]
                    if pool in self.symmetric_chat_clients:
                        print("Cancel request before connecting")
                        del self.symmetric_chat_clients[pool]
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

                    print "stun server {} receives request  from {} for pool: {}".format(self.index, device_type, pool)
                    print("current pool info: pool queue {} - symmetric pool {}".format(self.poolqueue, self.symmetric_chat_clients))
                    # full cone mode
                    if nat_type_id == '0':
                        try:
                            a, b = self.poolqueue[pool].addr, addr
                            nat_type_id_a, nat_type_id_b = self.poolqueue[pool].nat_type_id, nat_type_id
                            sockfd.sendto(self.addr2bytes(a, nat_type_id_a), b)
                            sockfd.sendto(self.addr2bytes(b, nat_type_id_b), a)
                            print "linked", pool
                            del self.poolqueue[pool]
                            del self.symmetric_chat_clients[pool]
                        # KeyError ==> pool not exist yet, initiate one
                        except KeyError:
                            self.poolqueue[pool] = ClientInfo(addr, nat_type_id)
                            self.symmetric_chat_clients[pool] = [nat_type_id, addr, False]
                    # symmetric NAT mode
                    else:
                        if pool in self.symmetric_chat_clients:
                            # pool created ==> device is occupied, decline another app's request
                            if device_type == '2':
                                print("device occupied")
                                sockfd.sendto("occupied", addr)
                                continue

                            if nat_type_id != '0' or self.symmetric_chat_clients[pool][0] != '0':
                                # at least one is symmetric NAT
                                recorded_client_addr = self.symmetric_chat_clients[pool][1]

                                if not self.symmetric_chat_clients[pool][2]:
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
                                    sockfd.sendto(self.addr2bytes((self.ip_addr, self.turn_port), '0'), recorded_client_addr)
                                    sockfd.sendto(self.addr2bytes((self.ip_addr, self.turn_port), '0'), addr)

                                    turn_thread = Thread(target=self.turn, args=(socket_turn,
                                                                                 recorded_client_addr,
                                                                                 addr,
                                                                                 self.symmetric_chat_clients,
                                                                                 pool,
                                                                                 self.index,
                                                                                 self.turn_id))
                                    turn_thread.setDaemon(True)
                                    print("Hurray! symmetric chat link established.")
                                    print("======== transfer to turn server =======")
                                    self.symmetric_chat_clients[pool] = ['0', (self.ip_addr, self.turn_port), True]
                                    self.turn_id = (self.turn_id + 1) % 999
                                    if pool in poolqueue:
                                        del self.poolqueue[pool]
                                    turn_thread.start()
                                else:
                                    print("retry request for the turn server from %s" % device_type)
                                    if device_type == '1':
                                        byte_sent = sockfd.sendto(self.addr2bytes(self.symmetric_chat_clients[pool][1], '0'), addr)
                                        print(byte_sent, len(self.addr2bytes(self.symmetric_chat_clients[pool][1], '0')))
                            else:
                                del self.symmetric_chat_clients[pool]  # neither clients are symmetric NAT
                        else:
                            if device_type == '1':
                                sockfd.sendto("canceled", addr)
                                continue
                            self.symmetric_chat_clients[pool] = [nat_type_id, addr, False]
                            sockfd.sendto("goodtogo", addr)
        except Exception as e:
            print("stun server on port %d is terminated, waiting for restart" % self.stun_port)
            print("Stun error: " + str(e))
            self.status[self.index] = False
            if sockfd is not None:
                sockfd.close()
            sys.exit()


if __name__ == "__main__":
    # global resources
    stun_ports = [7000, 8000, 9000, 10000, 11000, 12000, 13000]
    stun_status = [False, False, False, False, False, False, False]

    poolqueue = {}
    symmetric_chat_clients = {}

    for i, stun_port in enumerate(stun_ports):
        stun_thread = Thread(target=stun_turn, args=(i, stun_status, stun_port, stun_port + 1, poolqueue, symmetric_chat_clients))
        stun_thread.start()

    time.sleep(60)

    while True:
        for i, stun_port in enumerate(stun_ports):
            if not stun_status[i]:
                print("status on port %d fails, restarting...." % stun_ports[i], stun_status[i])
                stun_thread = Thread(target=stun_turn, args=(i, stun_status, stun_ports[i], stun_ports[i] + 1, poolqueue, symmetric_chat_clients))
                stun_thread.start()
        time.sleep(60)
