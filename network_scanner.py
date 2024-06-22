#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers.l2 import *

"""
Create ARP request directed to broadcast MAC asking for an IP
Send packets and receive response
Parse response
Print response
"""


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
    answered, unanswered = scapy.srp(arp_request_broadcast, timeout=1)
    print(f"answered: {answered.summary()}")
    print(f"unanswered: {unanswered.summary()}")



scan("192.168.0.1/24")
