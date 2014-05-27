#!/usr/bin/env python

import os
from scapy.all import *
from threading import Thread
import math
import time
import sys
from TCPSender import *
from GPSUtil import *

		
class Sniffer():
	
	
	def main(self):
		iface = "mon0"
		sniff(iface=iface,prn=self.trackClients,store=0)
	
	def convert_rssi(self,pwr):
		rssi_max = 60
		pwr = 100-pwr
		#sig_str assumed to be percentage (atheros) -> pwr / pwrmax * 100.0
		sig_str_dbm = (pwr/100.0 * rssi_max - 95)	
		pwr = math.log(1.0/sig_str_dbm**2)
				

	def trackClients(self, p):
		#We're only concerned by probe request packets
		#Also, sometime, addr2 is NoneType (don't know why actually)
		#p.type = 0 -> management frame
		if not p.haslayer(Dot11) or p.addr2 is None or p.addr2 not in ["68:a8:6d:6e:a9:d8"] :
			return
			
		#Ensure that this is a client
		if p.type == 0 and p.subtype in (0,2,4):
			#Signal strength
			sig_str = -(256-ord(p.notdecoded[-4:-3]))
			rssi_max = 60
			#sig_str assumed to be percentage (atheros) -> pwr / pwrmax * 100.0
			sig_str_dbm = -sig_str/100.0 * rssi_max - 95
			print "************************"
			print "\tRSSI raw : %f\n\tRSSI dbm : %f" % (sig_str, sig_str_dbm)
		
if __name__ == "__main__":
	Sniffer().main();

		
			
