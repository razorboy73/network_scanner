#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    scapy.arping(ip)
    
    
    
scan("172.16.149.2")

