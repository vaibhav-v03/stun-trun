#!/usr/bin/env python
# coding:utf-8

import socket
import struct
import sys
from collections import namedtuple

FullCone = "Full Cone"  # 0
RestrictNAT = "Restrict NAT"  # 1
RestrictPortNAT = "Restrict Port NAT"  # 2
SymmetricNAT = "Symmetric NAT"  # 3
UnknownNAT = "Unknown NAT" # 4
NATTYPE = (FullCone, RestrictNAT, RestrictPortNAT, SymmetricNAT, UnknownNAT)


def addr2bytes(addr, nat_type_id):
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


def main():
    port = sys.argv[1]
    try:
        port = int(sys.argv[1])
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
        if data.startswith("msg "):
            # forward symmetric chat msg, act as TURN server
            try:
                sockfd.sendto(data[4:], symmetric_chat_clients[addr])
                # print("msg successfully forwarded to {0}".format(symmetric_chat_clients[addr]))
                # print(data[4:])
            except KeyError:
                print("something is wrong with symmetric_chat_clients!")
        elif data.startswith("del "):
            print("Communication cancel requested!")

            pool = data[4:]
            if pool in poolqueue:
                del poolqueue[pool]
            if pool in symmetric_chat_clients:
                print("Cancel request before connecting")
                del symmetric_chat_clients[pool]
            if addr in symmetric_chat_clients:
                try:
                    recorded_client_addr = symmetric_chat_clients[addr]
                    print("Cancel request after connecting to " + recorded_client_addr[0])
                    del symmetric_chat_clients[recorded_client_addr]
                    del symmetric_chat_clients[addr]
                except KeyError:
                    print("Voice call pool is cleaned, key error")
                    continue
            sockfd.sendto("cancel!!", addr)
            print "Connection request canceled"
            print "Continue listening on *:%d (udp)" % port
        else:
            # help build connection between clients, act as STUN server
            print "connection from %s:%d" % addr
            try:
                pool, nat_type_id = data.strip().split()
            except:
                continue
            sockfd.sendto("ok {0}".format(pool), addr)
            print("pool={0}, nat_type={1}, ok sent to client".format(pool, NATTYPE[int(nat_type_id)]))
            data, addr = sockfd.recvfrom(2)
            if data != "ok":
                print("Didn't get ok back from client, actual msg is: " + data)
                print("Cleaning the pool...")
                if addr in symmetric_chat_clients:
                    try:
                        recorded_client_addr = symmetric_chat_clients[addr]
                        print("Cancel request after connecting to " + recorded_client_addr[0])
                        del symmetric_chat_clients[recorded_client_addr]
                        del symmetric_chat_clients[addr]
                    except KeyError:
                        print("Voice call pool is cleaned, key error")
                continue

            print "request received for pool:", pool

            try:
                a, b = poolqueue[pool].addr, addr
                nat_type_id_a, nat_type_id_b = poolqueue[pool].nat_type_id, nat_type_id
                sockfd.sendto(addr2bytes(a, nat_type_id_a), b)
                sockfd.sendto(addr2bytes(b, nat_type_id_b), a)
                print "linked", pool
                del poolqueue[pool]
            # KeyError ==> pool not exist yet, initiate one
            except KeyError:
                poolqueue[pool] = ClientInfo(addr, nat_type_id)

            if pool in symmetric_chat_clients:
                if nat_type_id == '3' or symmetric_chat_clients[pool][0] == '3':
                    # at least one is symmetric NAT
                    recorded_client_addr = symmetric_chat_clients[pool][1]
                    symmetric_chat_clients[addr] = recorded_client_addr
                    symmetric_chat_clients[recorded_client_addr] = addr
                    print("Hurray! symmetric chat link established.")
                    del symmetric_chat_clients[pool]
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
        main()
