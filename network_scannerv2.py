#!/usr/bin/env python
import argparse
import scapy.all as scapy
from scapy.layers.l2 import *

"""
Create ARP request directed to broadcast MAC asking for an IP
Send packets and receive response
Parse response
Print response
"""


def scan(ip):
    #set the IPfield to the ip address of interest
    #then create internet frame that we sent to broadcast address
    arp_request = scapy.ARP(pdst=ip)
    #show the details of the arp request
    arp_request.show()
    broadcast = scapy.Ether(dst =  "ff:ff:ff:ff:ff:ff")
    #show the details fo the broadcast request
    broadcast.show()
    #combine ether broadcast and ARP
    arp_request_broadcast = broadcast/arp_request
    arp_request_broadcast.show()
    print(arp_request_broadcast.summary())
    #broadcast the packet and capture its return value
    answered_list = scapy.srp(arp_request_broadcast, timeout = 2)[0]
    print(answered_list.summary())
    #parsse out the hardward and digital sources
    
    print("IP\t\t\tMAC Address\n-------------------------------------------------")
    for element in answered_list:
        print(element[1].psrc +"\t\t"+ element[1].hwsrc)
        
        print("-------------------------------------------------")
    

    
    
scan("172.16.149.163")