#!/usr/bin/env python

import os
import argparse
from scapy.all import *
import fileinput
from threading import Thread
from numpy import *
import time
import sys
	

class Log():
	
	def __init__(self, path):
		self.path = path
		self.log = open(path, "a")
		
	def write(self, client_addr, coord, signal_strength):
		self.log.write("%r\t%r\t%r\t%r\t%d" % \
			(client_addr, coord[0], coord[1], coord[2], signal_strength))
		self.log.write(os.linesep)
		self.log.flush()
		
class Sniffer():
	
	def __init__(self):
	
		#Detected wireless clients and their signal's power
		self.clientsSignalPower = {}
		
		#Virtual plane
		#self.plane = FakePlane()
		
		#Coordinates
		self.coord = (0,0,0)
	
		#Logging system
		self.logfile = ""

		#Buffer for stabilizing received signal strength / per user
		self.bufferSignal = {}
		self.BUFFER_SIZE = 1

		#My iPhone mac address
		self.TARGET_MAC = "68:a8:6d:6e:a9:d8"
		
		#Thread responsible for reading GPS coordinates
		self.t = Thread(target=self.readSTDIN, args = ())
		self.t.start()
		
	#Read STDIN until EOF char received
	def readSTDIN(self):
		try:
			buff = ''
			while True:
				buff += sys.stdin.read(1)
				if buff.endswith('\n'):
					self.coord = tuple(buff[:-1].split(','))
		except KeyboardInterrupt:
			sys.stdout.flush()
			pass		
	

	def main(self):
		#Sudo privileges needed
		#if os.geteuid() != 0:
			#exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
	
		parser = argparse.ArgumentParser()
		parser.add_argument("interface", help="Monitor mode enabled interface to use in order to sniff packets.")
		parser.add_argument("logfile", help="Path of log file")
		args = parser.parse_args()
		iface = args.interface
		self.logfile = args.logfile
		self.log = Log(self.logfile)
		#self.enableMonitorMode(iface)
		sniff(iface=iface,prn=self.trackClients,store=0)

	#To put card in monitor mode : 
	@staticmethod
	def enableMonitorMode(iface):
		os.system("ifconfig " + iface + " down")
		os.system("iwconfig " + iface + " mode monitor")
		os.system("ifconfig " + iface + " up")

	#Try to deauthenticate the client
	@staticmethod
	def deauth(p):
		sendp(RadioTap()/Dot11(type=0,subtype=12,addr1=p.addr2,addr2=p.addr3,addr3=p.addr3)/Dot11Deauth())
	
	def bufferPower(self, user, powerVal):
		print "Should log %r %d" % (user,powerVal)
		self.log.write(user, self.coord, powerVal)
		#if user in self.bufferSignal:
			#self.bufferSignal[user].append(powerVal)
			#if len(self.bufferSignal[user]) == self.BUFFER_SIZE:
				#maxPower = max(self.bufferSignal[user])
				#self.clientsSignalPower[user].append(maxPower)
				##Here log with GPS coordinates
				#self.log.write(user, self.coord, maxPower)
				#print "Should log %r %d" % (user,maxPower)
				#self.bufferSignal[user] = []
		#else:
			#self.bufferSignal[user] = []
			#self.bufferSignal[user].append(powerVal)
			#self.clientsSignalPower[user] = []
		
	
	def trackClients(self, p):
		#We're only concerned by probe request packets
		#Also, sometime, addr2 is NoneType (don't know why actually)
		#p.type = 0 -> management frame
		if not p.haslayer(Dot11) or p.addr2 is None :
			return
			
		#if p.addr2 != self.TARGET_MAC:
			#return
			
		#Ensure that this is a client
		if p.type == 0 and p.subtype in (0,2,4):
			
			#Signal strength
			sig_str = 100-(256-ord(p.notdecoded[-4:-3]))
			#print p.addr2 + " detected! Signal power : " + str(sig_str)
			self.bufferPower(p.addr2, sig_str)
			
if __name__ == "__main__":
	Sniffer().main();

