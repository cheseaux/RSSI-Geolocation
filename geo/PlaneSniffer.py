#!/usr/bin/env python

import os
from scapy.all import *
from threading import Thread
import math
import time
import sys
from TCPSender import *
	
class GPSUtil():
	
	@staticmethod
	def gpsToCartesian(lat,lon):
		earthR = 6371
		x = earthR *(math.cos(math.radians(lat)) * math.cos(math.radians(lon)))
		y = earthR *(math.cos(math.radians(lat)) * math.sin(math.radians(lon)))
		z = earthR *(math.sin(math.radians(lat)))
		
		return [x,y,z]

	@staticmethod
	def haversine_meter(gps1, gps2):
		dlong = math.radians(gps2.lon - gps1.lon);
		dlat = math.radians(gps2.lat - gps1.lat);
		a = pow(math.sin(dlat / 2.0), 2) + math.cos(math.radians(gps1.lat)) * math.cos(math.radians(gps2.lat)) * pow(math.sin(dlong / 2.0), 2);
		c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a));
		d = 6367000 * c;
		return float(d);
		
	@staticmethod
	def remove_duplicate_GPS(log):
		s = set()
		topN = []
		for (lat,lon,alt, pwr, mac) in log:
			if not s.intersection((lat,lon)):
				s.update((lat,lon))
				topN.append((lat,lon,alt, pwr, mac))
			
		return topN
		
		
	@staticmethod
	def angleBetweenCoords(lat1,lon1,lat2,lon2):
		dy = lat2 - lat1
		dx = math.cos(math.pi/180*lat1)*(lon2 - lon1)
		return math.degrees(math.atan2(dy, dx))
		
	@staticmethod
	def weighted_sum(values, weights):
		res = 0
		totalWeight = sum(weights)
		for i in range(len(values)):
			res += values[i] * weights[i] / totalWeight
		return res
	
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
	
		#Detected wireless clients and their signal's power + coordinates of the plane
		self.clientsSignalPower = {}
		
		#TCP sender for communication with base station
		self.sender = TCPSender()
		
		#Min acceptable power to localize users
		self.MIN_POWER = 0
		
		#Coordinates
		self.coord = (0,0,0)
		self.angle = 0
	
		#Logging system
		self.logfile = ""
		
		#Thread responsible for reading GPS coordinates
		self.t = Thread(target=self.readSTDIN, args = ())
		self.t.start()
		
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
					self.send_position_to_station(self.coord[0], self.coord[1], self.angle)
					buff = ''
		except KeyboardInterrupt:
			sys.stdout.flush()
			pass
	
	def localize_user(self, user):
		
		usr = list(set(self.clientsSignalPower[user]))
		usr.sort(key=lambda tup: tup[3], reverse=True)
		usr = GPSUtil.remove_duplicate_GPS(usr)
		
		if (len(usr) < 3):
			return
		
		#for i in xrange(3,len(usr)):	
		allLat = 0
		allLon = 0	 	
		
		pwrs = []		
		for (lat,lon,alt,pwr,mac) in usr[0:len(usr)]:	
			pwrs.append(pwr)
			
			allLat += pwr * lat
			allLon += pwr * lon
			
		allLat = allLat / sum(pwrs)
		allLon = allLon / sum(pwrs)		

		self.send_localization_to_station(user,allLat,allLon)
	
	def send_position_to_station(self, lat, lon, angle):
		self.sender.send("[plane]%s\t%s\t%s\t%d" % ("plane", lat, lon, angle))

	def send_localization_to_station(self,user, lat, lon):
		self.sender.send("[user]%s\t%s\t%s" % (user, lat, lon))
		#print "Sended %r\t%r\t%r" % (user, lat, lon)


	def main(self):
		#Sudo privileges needed
		#if os.geteuid() != 0:
			#exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
	
		iface = sys.argv[1]
		self.logfile = sys.argv[2]
		self.log = Log(self.logfile)
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
			#print p.addr2 + " detected! Signal power : " + str(sig_str)
			if sig_str >= self.MIN_POWER:
				self.log.write(p.addr2, self.coord, sig_str)
				if not p.addr2 in self.clientsSignalPower:
					self.clientsSignalPower[p.addr2] = []
				self.clientsSignalPower[p.addr2].append((self.coord[0], self.coord[1], self.coord[2], sig_str, p.addr2))
				#if len(self.clientsSignalPower[p.addr2]) >= 4:
				print "Localize user %r" % p.addr2
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
