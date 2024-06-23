#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers.l2 import *

"""
Create ARP request directed to broadcast MAC asking for an IP
Send packets and receive response
Parse response
Print response
"""

def main():
    address_output(scan("192.168.0.1/24"))
def scan(ip):
    # create an arp request directed to broadcast MAC asking for IP
    # Part 1 - ask who has the target IP
    arp_request = ARP(pdst=ip)
    arp_request.show()
    # print(arp_request.summary())
    # Part 2 - set destination MAC to Broadcast MAC; involves combining frames to broadcast
    # packets.  Involes creating a frame
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast.show()
    scapy.ls(scapy.Ether())
    # print(broadcast.summary())
    # create the frame
    arp_request_broadcast = broadcast/arp_request
    print(arp_request_broadcast.summary())
    arp_request_broadcast.show()
    # send packet and capture response
    answered_list = scapy.srp(arp_request_broadcast, timeout=1)[0]
    return answered_list

def address_output(answered_list):
    print(answered_list)
    # print(unanswered_list)
    # print(f"answered: {answered_list.summary()}")
    # print(f"unanswered: {unanswered_list.summary()}")

    ###[ Ethernet ]###
    # dst = 00:0c: 29:3e:70:c0
    # src = de:36: 0c:7a:26:01
    # type = ARP
    # ###[ ARP ]###
    # hwtype = Ethernet(10Mb)
    # ptype = IPv4
    # hwlen = 6
    # plen = 4
    # op = is -at
    # hwsrc = de:36:0c:7a: 26:01
    # psrc = 192.168.0.1
    # hwdst = 00:0c:29:3e:70:c0
    # pdst = 192.168.0.32
    # ###[ Padding ]###
    # load = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    for element in answered_list:
        print(f"MAC address: {element[1].hwsrc}")
        print(f"IP Address: {element[1].psrc}")
        print("****************************************************")






if __name__ == "__main__":
    main()