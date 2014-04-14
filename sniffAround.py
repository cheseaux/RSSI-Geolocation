#!/usr/bin/env python

import os
import argparse
from scapy.all import *
import fileinput
from threading import Thread
from math import cos, pi, sin
import time
import sys

class FakePlane():

	def __init__(self):
		self.angle = 0.0
		self.r = 0.002
		self.center = (46.518394,6.568469)
		
		Thread(target=self.nextCoordinateCircle, args = ()).start()
		
	def nextCoordinateCircle(self):
		while True:
			self.x = self.center[0] + self.r * cos(self.angle)
			self.y = self.center[1] + self.r * sin(self.angle)
			self.angle += 0.1
			if self.angle >= 2*pi:
				self.angle = 0.0
			#print "%f : %f" % (self.x,self.y)
			
			time.sleep(1)
			
	def getCoord(self):
		return (self.x, self.y)

class Log():
	
	def __init__(self, path):
		self.path = path
		self.log = open(path, "a")
		
	def write(self, client_addr, lat, lon, signal_strength):
		self.log.write("%r\t%f\t%f\t%d" % (client_addr, lat, lon, signal_strength))
		self.log.write(os.linesep)
		
class Sniffer():
	
	def __init__(self):
	
		#Detected wireless clients and their signal's power
		self.clientsSignalPower = {}
		
		#Virtual plane
		self.plane = FakePlane()
		
		#Coordinates
		self.coord = "X:X"
	
		#Logging system
		self.log = Log('clients.log')
	
		#Buffer for stabilizing received signal strength / per user
		self.bufferSignal = {}
		self.BUFFER_SIZE = 8

		#My iPhone mac address
		self.TARGET_MAC = "68:a8:6d:6e:a9:d8"
		
		#Thread responsible for reading GPS coordinates
		#self.t = Thread(target=self.readSTDIN, args = ())
		#self.t.start()
		
	#Read STDIN until EOF char received
	#@staticmethod
	#def readSTDIN():
		#while True:
			#self.coord = raw_input("Enter coordinates here : \n>")
			#print "Received : %r" % self.coord

	def main(self):
		#Sudo privileges needed
		if os.geteuid() != 0:
			exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
	
		parser = argparse.ArgumentParser()
		parser.add_argument("interface", help="Interface to use in order to sniff packets. Should handle monitor mode.")
		args = parser.parse_args()
		iface = args.interface

		self.enableMonitorMode(iface)
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
		if user in self.bufferSignal:
			self.bufferSignal[user].append(powerVal)
			if len(self.bufferSignal[user]) == self.BUFFER_SIZE:
				maxPower = max(self.bufferSignal[user])
				self.clientsSignalPower[user].append(maxPower)
				#Here log with GPS coordinates
				(x,y) = self.plane.getCoord()
				self.log.write(user, x,y, maxPower)
				print "Should log %d at %f:%f" % (maxPower, x,y)
				self.bufferSignal[user] = []
		else:
			self.bufferSignal[user] = []
			self.bufferSignal[user].append(powerVal)
			self.clientsSignalPower[user] = []
		
	
	def trackClients(self, p):
		#We're only concerned by probe request packets
		#Also, sometime, addr2 is NoneType (don't know why actually)
		#p.type = 0 -> management frame
		if not p.haslayer(Dot11) or p.addr2 is None :
			return
			
		if p.addr2 != self.TARGET_MAC:
			return
			
		#Ensure that this is a client
		if p.type == 0 and p.subtype in (0,2,4):
			
			#Signal strength
			sig_str = 100-(256-ord(p.notdecoded[-4:-3]))
			#print p.addr2 + " detected! Signal power : " + str(sig_str)
			self.bufferPower(p.addr2, sig_str)
			
if __name__ == "__main__":
	Sniffer().main();

