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
def main():
    ip_range = get_command_line_args()
    address_output(scan(ip_range))
    
def get_command_line_args():
    parser = argparse.ArgumentParser(description='Input the ip ranges you want to scan in CIDR notation')
    parser.add_argument("-ip", "--ip_range", dest="ip", type=str, help='The ip range you want to scan in CIDR')

    args = parser.parse_args()
    print(f'IP Ranges: {args.ip}')
    if not args.ip:
        parser.error("[-] Please specify an IP range --help for assistance")
    # handled errors for the mac address within the arguments
    return args.ip    
    
    

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
    clients_lists = []
    print("IP\t\t\tMAC Address\n-------------------------------------------------")
    for element in answered_list:
        #create a dictionary
        client_dict = {"ip":element[1].psrc, "mac_address": element[1].hwsrc }
        #apennd dictionary to list
        clients_lists.append(client_dict)
        print(element[1].psrc +"\t\t"+ element[1].hwsrc)

        
        print("-------------------------------------------------")
    return (clients_lists)

def address_output(clients_lists):
    print("IP\t\t\tMAC Address\n-------------------------------------------------")
    for client in clients_lists:
        print(f"{client['ip']}\t\t{client['mac_address']}")
    print("------------------------------------------------")
        
    
if __name__ == "__main__":
    main()

    
    
