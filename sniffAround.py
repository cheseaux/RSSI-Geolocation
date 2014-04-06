#!/usr/bin/env python

import os
import argparse
from scapy.all import *

#Detected wireless clients
observedClients = []

#iPhone mac address
TARGET_MAC = "68:a8:6d:6e:a9:d8"

def main():
	#Sudo privileges needed
	if os.geteuid() != 0:
		exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

	parser = argparse.ArgumentParser()
	parser.add_argument("interface", help="Interface to use in order to sniff packets. Should handle monitor mode.")
	args = parser.parse_args()
	iface = args.interface
	
	enableMonitorMode(iface)
	sniff(iface=iface,prn=trackSignalPower)

#Scapy lib for packet injection/sniffing
#To put card in monitor mode : 
def enableMonitorMode(iface):
	os.system("ifconfig " + iface + " down")
	os.system("iwconfig " + iface + " mode monitor")
	os.system("ifconfig " + iface + " up")

#Try to deauthenticate the client
def deauth(p):
    sendp(RadioTap()/Dot11(type=0,subtype=12,addr1=p.addr2,addr2=p.addr3,addr3=p.addr3)/Dot11Deauth())

#This method should create a fake AP
#Problem is to guess SSID that user is used to connect to.
#No device sends directed probes with registered SSID
#(Except iPhone with built-in SSID directed probe for Swisscom hotspots
def registerClients(p):
    #We're only concerned by probe request packets
    #Also, sometime, addr2 is NoneType (don't know why actually)
    if not p.haslayer(Dot11) or p.addr2 is None :
		return
    
    if p.addr2 not in observedClients:
		#Signal strength
		sig_str = -(256-ord(p.notdecoded[-4:-3]))
        print p.addr2 + " detected! Signal power : " + str(sig_str)
		observedClients.append(p.addr2)

#Track signal power of target
#We should keep the minimum (absolute) value to be the actual signal strength
#at each interval of time so we can use it to triangulate position of victims
def trackSignalPower(p):
    
    #We're only concerned by probe request packets
    #Also, sometime, addr2 is NoneType (don't know why actually)
    if not p.haslayer(Dot11) or p.addr2 is None :
		return
    
    #Filter only my iPhone's probe for testing purpose
    if p.addr2 == TARGET_MAC:
        #Signal strength
        sig_str = -(256-ord(p.notdecoded[-4:-3]))
        print p.addr2 + " : probe received. [power : " + str(sig_str) + "]"

if __name__ == "__main__":
    main();

