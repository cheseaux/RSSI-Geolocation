#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
import sys

class APSpoofer():
	
	def __init__(self, name):
		self.name = name
		
class AP():
	
	HEADER_PRINTED = False
	
	def __init__(self,ssid,bssid,encrypted):
		self.ssid = ssid
		self.bssid = bssid
		self.encrypted = encrypted
		
	def __str__(self):
		if not AP.HEADER_PRINTED:
			print "BSSID\t\tSSID"
			AP.HEADER_PRINTED = True
		return "%r\t%r" % (self.bssid, self.ssid + ("(encrypted)" if self.encrypted else "(open)"))
		
class APSniffer():
	
	def __init__(self, iface):
		self.iface = iface
		self.registered_ap = {}
		self.client_ssid = {}
	
	def trackAP(self,p):
		if p.haslayer(Dot11):
			
			#Probe response
			if p.type == 0 and p.subtype == 8:
				ssid	   = str(p[Dot11Elt].info)
				bssid	  = p[Dot11].addr3	
				encrypted = self.is_ap_encrypted(p)
				
				if not bssid in self.registered_ap:
					ap = AP(ssid,bssid,encrypted)
					self.registered_ap[bssid] = ap
					print ap
					
			#Probe Request
			if p.type == 0 and p.subtype == 4:
				ssid = str(p[Dot11Elt].info)
				if not ssid == "":
					if self.client_ssid.has_key(p.addr2):
						if not ssid in self.client_ssid[p.addr2]:
							self.client_ssid[p.addr2].append(ssid)
							print p.addr2 + " also wants to connect to " + ssid
					else:
						self.client_ssid[p.addr2] = []
						self.client_ssid[p.addr2].append(ssid)
						print p.addr2 + " wants to connect to " + ssid
					
	def main(self):
		sniff(iface=self.iface, prn=self.trackAP, store=0)
		
	def is_ap_encrypted(self, p):
		capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
				{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
		if re.search("privacy", capability): return True
		else: return False

if __name__ == '__main__':
	APSniffer('mon0').main()

