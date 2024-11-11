#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
from switchyard.lib.address import *
from switchyard.lib.packet import *

class forwarding_table_entry(object):
    def __init__(self, prefix, mask, next_ip, target):
        self.prefix = prefix
        self.mask = mask
        self.next_ip = next_ip
        self.target = target

class Packet_queue(object):
    class Entry(object):
        def __init__(self, packet, table_entry, last_request_time, request_nums = 0):
            self.packets = [packet]
            self.last_request_time = last_request_time
            self.request_nums = request_nums
            self.table_entry = table_entry
    def __init__(self):
        self.lst = []
    
    def handle(self, packet:Packet, table_entry, net, in_arp_table = False):
        flag = 0
        for entry in self.lst[:]:
            entry:Packet_queue.Entry
            if packet in entry.packets:
                flag = 1
                if time.time() - entry.last_request_time >= 1:
                    if entry.request_nums < 5:
                        target_ip = table_entry.next_ip if table_entry.next_ip else packet[IPv4].dst
                        arp = Arp(operation = ArpOperation.Request, 
                                senderhwaddr = table_entry.target.ethaddr,
                                senderprotoaddr = table_entry.target.ipaddr,
                                targethwaddr = "ff:ff:ff:ff:ff:ff",
                                targetprotoaddr = target_ip)
                        arp_request = Ethernet(src=table_entry.target.ethaddr,
                                                dst="ff:ff:ff:ff:ff:ff",
                                                ethertype=EtherType.ARP) + arp
                        log_info(f"send arp request to {target_ip}")
                        net.send_packet(table_entry.target.name, arp_request)
                        entry.last_request_time = time.time()
                        entry.request_nums += 1
                    elif entry.request_nums >= 5:
                        log_info(f"remove entry to {entry.packets[0][IPv4].dst}")
                        self.lst.remove(entry)
            elif packet[IPv4].dst == entry.packets[0][IPv4].dst:
                flag = 1
                entry.packets.append(packet)
        if flag == 0:
            new_entry = self.Entry(packet, table_entry, time.time() - 1, 0)
            self.lst.append(new_entry)
            if not in_arp_table:
                self.handle(new_entry.packets[0], new_entry.table_entry, net)


packet_queue = Packet_queue()

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_table = {}
        self.interfaces = net.interfaces()
        self.ips = [i.ipaddr for i in self.interfaces]
        self.macs = [i.ethaddr for i in self.interfaces]
        self.forwarding_table = []
        for i in self.interfaces:
            print(i.name ,i.ipaddr, i.ethaddr)
        def forwarding_table_init():
            for interface in self.interfaces:
                ipaddr = IPv4Address(interface.ipaddr)
                netmask = IPv4Address(interface.netmask)
                prefix = IPv4Address(int(ipaddr) & int(netmask))
                entry = forwarding_table_entry(prefix, netmask, None, interface)
                self.forwarding_table.append(entry)

            f = open("forwarding_table.txt")
            lines = f.readlines()
            for line in lines:
                line = line.strip('\n')
                items = line.split(" ")
                ipaddr = IPv4Address(items[0])
                netmask = IPv4Address(items[1])
                next_ip = IPv4Address(items[2])
                for interface in self.interfaces:
                    if interface.name == items[3]:
                        target = interface
                        break
                else:
                    target = None
                prefix = IPv4Address(int(ipaddr) & int(netmask))
                entry = forwarding_table_entry(prefix, netmask, next_ip, target)

                self.forwarding_table.append(entry)
            
        forwarding_table_init()

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        packet: Packet
        for i in self.interfaces:
            if ifaceName == i.name:
                interface = i
        log_info(f"packet recived on {ifaceName} : {str(packet)}")
        eth = packet.get_header(Ethernet)
        if (eth.dst == "ff:ff:ff:ff:ff:ff" or eth.dst == interface.ethaddr) and eth.ethertype != EtherType.x8021Q:
            if packet.has_header(IPv4):
                head: IPv4 = packet.get_header(IPv4)
                if head.dst not in self.ips:
                    head.ttl -= 1
                    matched = False
                    prefix_len = 0
                    matched_entry = None
                    for entry in self.forwarding_table:
                        entry:forwarding_table_entry
                        prefix = int(head.dst) & int(entry.mask)
                        prefixnet = IPv4Network(f"{entry.prefix}/{entry.mask}")
                        if prefix == int(entry.prefix) and prefixnet.prefixlen > prefix_len:
                            prefix_len = prefixnet.prefixlen
                            matched_entry = entry
                            matched = True
                    if matched:
                        entry = matched_entry
                        log_info(f"packet to {head.dst} matched {entry.target}")
                        target_ip = entry.next_ip if entry.next_ip else head.dst
                        packet_queue.handle(packet, entry, self.net, target_ip in self.arp_table.keys())
                            
            arp = packet.get_header(Arp)
            if arp:
                mac_match = False
                ip_match = False
                if eth.dst == arp.targethwaddr:
                    if arp.targethwaddr == "ff:ff:ff:ff:ff:ff" or arp.targethwaddr == str(interface.ethaddr):
                        mac_match = True
                if mac_match:
                    if arp.targetprotoaddr in self.ips:
                        ip_match = True
                if mac_match and ip_match:
                    if arp.operation == 1:
                        self.arp_table[arp.senderprotoaddr] = arp.senderhwaddr
                        log_info("arp request")
                        flag = 0
                        for i in range(len(self.ips)):
                            if self.ips[i] == arp.targetprotoaddr:
                                log_info(f"interface {ifaceName} matched")
                                reply = create_ip_arp_reply(self.macs[i], arp.senderhwaddr, self.ips[i], arp.senderprotoaddr)
                                log_info(f"send packet to {ifaceName} : {str(reply)}")
                                self.net.send_packet(ifaceName, reply)
                                flag = 1
                                break
                        if flag == 0:
                            log_info("target not found")
                    elif arp.operation == 2:
                        log_info("arp reply")
                        if arp.senderhwaddr != "ff:ff:ff:ff:ff:ff":
                            self.arp_table[arp.senderprotoaddr] = arp.senderhwaddr
                        self.arp_table[arp.targetprotoaddr] = arp.targethwaddr
                        for key in self.arp_table.keys():
                            print(key, self.arp_table[key])

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            entry_tobe_remove = None
            for que_entry in packet_queue.lst[:]:
                dst = que_entry.packets[0][IPv4].dst
                packet_tobe_remove = None
                for packet in que_entry.packets[:]:
                    head: IPv4 = packet.get_header(IPv4)
                    log_info(f"packets to {head.dst} nums: {len(que_entry.packets)}")
                    entry = que_entry.table_entry
                    if not entry.next_ip:
                        next_ip = head.dst
                    else:
                        next_ip = entry.next_ip
                    if next_ip in self.arp_table.keys():
                        next_mac = self.arp_table[next_ip]
                        eth_header = packet.get_header(Ethernet)
                        eth_header.src = entry.target.ethaddr
                        eth_header.dst = next_mac
                        log_info(f"packet to {head.dst} forwarding to {next_ip}")
                        self.net.send_packet(entry.target, packet)
                        que_entry.packets.remove(packet)
                    else:
                        packet_queue.handle(packet, entry, self.net)
                        break
                if not que_entry.packets:
                    log_info(f"remove entry to {dst}")
                    packet_queue.lst.remove(que_entry)
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
