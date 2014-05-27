#!/usr/bin/env python

import os
from scapy.all import *
from threading import Thread
import math
import time
import sys
from TCPSender import *
from GPSUtil import *
	
class Log():
	
	def __init__(self, path):
		self.path = path
		self.log = open(path, "a")
		self.ts = lambda: int(round(time.time() * 1000))

	def writeLocalization(self, user, coord):
		self.log.write("[LOCAL]\t%d\t%r\t%f\t%f\t" % (self.ts(), user, coord[0], coord[1]))
		self.log.write(os.linesep)
		self.log.flush()
		
	def writePlanePosition(self, planeID, coord, angle):
		self.log.write("[COORD]\t%d\t%r\t%f\t%f\t%f\t%d" % \
			(self.ts(),planeID, coord[0], coord[1], coord[2], angle))
		self.log.write(os.linesep)
		self.log.flush()

	def writeBeacon(self, client_addr, coord, signal_strength):
		self.log.write("[BEACON]\t%d\t%r\t%r\t%r\t%r\t%d" % \
			(self.ts(),client_addr, coord[0], coord[1], coord[2], signal_strength))
		self.log.write(os.linesep)
		self.log.flush()
		
class Sniffer():
	

	def __init__(self):
	
		#Detected wireless clients and their signal's power + coordinates of the plane
		self.clientsSignalPower = {}
		
		#TCP sender for communication with base station
		self.sender = TCPSender()
		self.sender.start()
		
		#Min acceptable power to localize users
		self.MIN_POWER = 0
		
		#Coordinates
		self.coord = (0,0,0)
		self.angle = 0
	
		#Logging system
		self.logfile = ""
		
	
		
	#Read STDIN until EOF char received
	#Receive plane's coordinate
	def readSTDIN(self):
		try:
			buff = ''
			while True:
				buff += sys.stdin.read(1)
				if buff.endswith('\n'):
					buff = buff[:-1].split('\n')[-1]
					buff = buff.split(', ')
					self.angle = GPSUtil.angleBetweenCoords(self.coord[0], self.coord[1], float(buff[0]), float(buff[1]))
					self.coord = tuple((float(buff[0]), float(buff[1]), float(buff[2])))
					self.send_position_to_station(self.coord, self.angle)
					buff = ''
		except KeyboardInterrupt:
			sys.stdout.flush()
			pass
	
	def localize_user(self, user):
		usr = self.clientsSignalPower[user]
		func = lambda x : (x/100.0)
		center_of_mass = GPSUtil.compute_center_of_mass(usr, func, 30, 20)
		print "Center of mass : ",
		print center_of_mass
		if not center_of_mass == None:
			coord = center_of_mass
			self.send_localization_to_station(user,coord)
	
	def send_position_to_station(self, coord, angle):
		self.sender.send("[plane]%s\t%s\t%s\t%d" % (self.planeID, coord[0], coord[1], angle))
		self.log.writePlanePosition(self.planeID,coord, angle)

	def send_localization_to_station(self,user, coord):
		self.sender.send("[user]%s\t%s\t%s" % (user, coord[0], coord[1]))
		self.log.writeLocalization(user,coord)
		
	def main(self):
		self.planeID = sys.argv[1]
		iface = sys.argv[2]
		self.logfile = sys.argv[3]
		self.log = Log(self.logfile)
		
		#Thread responsible for reading GPS coordinates
		self.t = Thread(target=self.readSTDIN, args = ())
		self.t.start()
		
		sniff(iface=iface,prn=self.trackClients,store=0)
		

	def trackClients(self, p):
		#We're only concerned by probe request packets
		#Also, sometime, addr2 is NoneType (don't know why actually)
		#p.type = 0 -> management frame
		if not p.haslayer(Dot11) or p.addr2 is None :
			return
			
		#Ensure that this is a client
		if p.type == 0 and p.subtype in (0,2,4):
			#Signal strength
			sig_str = 100-(256-ord(p.notdecoded[-4:-3]))
			if sig_str >= self.MIN_POWER:
				self.log.writeBeacon(p.addr2, self.coord, sig_str)
				if not p.addr2 in self.clientsSignalPower:
					self.clientsSignalPower[p.addr2] = []
				self.clientsSignalPower[p.addr2].append((self.coord[0], self.coord[1], self.coord[2], sig_str, p.addr2))
				self.localize_user(p.addr2)
				
if __name__ == "__main__":
	Sniffer().main();


	#Deprecated stuff...
	
	##put card in monitor mode : 
	#@staticmethod
	#def enableMonitorMode(iface):
		#os.system("ifconfig " + iface + " down")
		#os.system("iwconfig " + iface + " mode monitor")
		#os.system("ifconfig " + iface + " up")

	##Try to deauthenticate the client
	#@staticmethod
	#def deauth(p):
		#sendp(RadioTap()/Dot11(type=0,subtype=12,addr1=p.addr2,addr2=p.addr3,addr3=p.addr3)/Dot11Deauth())
