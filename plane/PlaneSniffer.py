#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = "Jonathan Cheseaux"
__copyright__ = "Copyright 2014"
__credits__ = ["Jonathan Cheseaux", "Stefano Rosati", "Karol Kruzelecki"]
__license__ = "MIT"
__email__ = "cheseauxjonathan@gmail.com"


import os
from scapy.all import *
from threading import *
import math
import time
import sys
from TCPSender import *
from GPSUtil import *

#Will raise an exception if ran from the gumstix
#Uggly Hack but works
try:
	import csv
	from GoogleMapDisplay import *
except ImportError:
	pass


FLIGHT_MODE = False

if not FLIGHT_MODE:
	app = None	

#From : http://stackoverflow.com/questions/4625182/python-lock-method-annotation
def synchronized(method):
    """ Implement Java Synchronization for python methods """

    def new_method(self, *arg, **kws):
        with self.lock:
            return method(self, *arg, **kws)


    return new_method

class Log():
	"""
	Utility that allows the plane to save events in a log file.
	The events are (beacon received, position updated, localization done)
	
	The methods are self-explanatory
	"""
	
	lock = threading.RLock()
	
	def __init__(self, path):
		self.path = path
		self.log = open(path, "a")
		self.ts = lambda: int(round(time.time() * 1000))

	@synchronized
	def writeLocalization(self, user, coord):
		self.log.write("[LOCAL]\t%d\t%r\t%f\t%f\t" % (self.ts(), user, coord[0], coord[1]))
		self.log.write(os.linesep)
		self.log.flush()
	
	@synchronized
	def writePlanePosition(self, planeID, coord, angle):
		
		self.log.write("[COORD]\t%d\t%r\t%.8f\t%.8f\t%.8f\t%d" % \
			(self.ts(),planeID, coord[0], coord[1], coord[2], angle))
		print "Sending coord : %.8f %.8f %.8f" % (coord[0], coord[1], angle)
		self.log.write(os.linesep)
		self.log.flush()

	@synchronized
	def writeBeacon(self, client_addr, coord, signal_strength):
		self.log.write("[BEACON]\t%d\t%r\t%r\t%r\t%r\t%d" % \
			(self.ts(),client_addr, coord[0], coord[1], coord[2], signal_strength))
		self.log.write(os.linesep)
		self.log.flush()
		
class Sniffer():
	"""This class contains the core algorithms reponsible for geolocalizing
	people on the ground, using the beacon frames received by their
	smartphone and sniffed by a radio interface.
	
	GPS position (lat, lon, alt, heading) should be passed through stdin.
	It also provide a communication channel (TCP) with the base station.
	
	If you want to use this script on the plane (gumstix) you should set
	FLIGHT_MODE to TRUE.
	If you want to compute the localization from the log file, you should set it
	to False.
	"""

	def __init__(self):
	
		#Detected wireless clients and their signal's power + coordinates of the plane
		self.clientsSignalPower = {}
		
		#Decrease search area (radius, in meters)
		self.reducing_search = False
		self.search_radius = 249 
		
		#Min acceptable power to localize users
		self.MIN_POWER = 0
		
		#Coordinates
		self.coord = (0,0,0)
		self.angle = 0
	
		#Logging system
		self.logfile = ""
		
	
	def readSTDIN(self):
		"""
		Read STDIN until EOF char received
		Receive plane's coordinate from the GPS
		"""
		try:
			buff = ''
			while True:
				buff += sys.stdin.read(1)
				if buff.endswith('\n'):
					buff = buff[:-1].split('\n')[-1]
					buff = buff.split(', ')
					self.angle = float(buff[5])
					self.coord = tuple((float(buff[0]), float(buff[1]), float(buff[2])))
					t = Thread(target=self.send_position_to_station, args = (self.coord, self.angle))
					t.start()
					buff = ''
		except KeyboardInterrupt:
			sys.stdout.flush()
			pass
			
	def reduceSearchArea(self, target='c4:88:e5:24:3d:83'):
		"""
		Route the plane on a smaller circle each 2 minutes 
		And localize the target user. The latest localization
		will be the new center of the next circle.
		"""
		while True:
			
			(lat,lon) = self.localize_user(target,30,100)
			self.writeFileForPilot(lat,lon,self.search_radius)
			print "Reducing search area to circle : %f,%f radius : %f" % (lat,lon,self.search_radius)
			self.search_radius = self.search_radius * 0.5 #reduce radius for next iteration
			if (self.search_radius < 20.0):
				sys.exit(0) #End of search !
				
			time.sleep(1*60*2)
			
			
	def readRoutingInstructions(self):
		"""
		Wait for routing instruction send by the base station on the
		TCP connection.
		"""
		while True:
			instructions = self.sender.receive()
			if not instructions == None:
				(event, lat,lon	,radius) = instructions
				print "Received routing instructions ! %r %r %r" % (lat,lon,radius)
				#compute the center:
				radius = float(radius)
				radius = min(radius, 249)
				self.writeFileForPilot(lat,lon,radius)
				self.t = Thread(target=self.reduceSearchArea, args = (''))
				self.t.start()
				
	def writeFileForPilot(self, center_x, center_y, radius, altitude=50):
		"""This is the command that allows to pass a new waypoint to the
		plane's autopilot"""
		command = "/smavnet/gapi_sendcoordinates %.8f %.8f %.8f %.8f" % (float(center_x), float(center_y), altitude, float(radius))
		os.system(command)

	def compute_center_of_mass(self,samples, sort_tuple, map_pwr_func, pwr_thresh, beacon_thresh, beacon_rpt_int):
		"""Compute the geolocalization of every user that the plane is
		aware of
		
		Keyword arguments:
		samples 	-- the list of beacon frames received
				       following the format : (
		sort_tuple 	-- number of the tuple by which the samples should
					  be sorted
		map_pwr_func -- mapping function of the power
		pwr_thresh -- power threshold (min power)
		beacon_thresh -- number of beacon frames considered
		beacon_rpt_int -- unused
		"""
		
		usr = list(set(samples))
		usr.sort(key=lambda tup: tup[sort_tuple], reverse=True)
		usr = GPSUtil.remove_duplicate_GPS(usr, beacon_rpt_int)
		
		allLat = 0
		allLon = 0	 	
		
		pwrs = []		
		for (lat,lon,alt,pwr,mac) in usr[0:min(len(usr),beacon_thresh)]:
			if pwr >= pwr_thresh and lat > 0.0 and lon > 0.0:
				pwr = map_pwr_func(pwr)
				
				###DISABLED IN FLIGHT MODE !
				if not FLIGHT_MODE:
					self.gMapDisplay.addLabel(lat, lon, text="%f %f" % (lat, pwr))
				#############################
				
				pwrs.append(pwr)
				allLat += pwr * lat
				allLon += pwr * lon
				
		if sum(pwrs) == 0:
			return None

		return (allLat / sum(pwrs), allLon / sum(pwrs))

	def localize_user(self, user, pwr_thresh=20, beacon_thresh=15, beacon_rpt_int=5, sort_tuple=3):
		"""Compute the localization of a specific user """
		samples = self.clientsSignalPower[user]
		pwr_func = lambda x : x * 2**math.log(x/10.0)# if x > 30 else x
		return self.compute_center_of_mass(samples=samples, sort_tuple=sort_tuple, map_pwr_func=pwr_func, pwr_thresh=pwr_thresh, beacon_thresh=beacon_thresh, beacon_rpt_int=beacon_rpt_int)
		
	def send_beacon_to_station(self, user, coord, pwr):
		self.sender.send("[beacon]%s\t%s\t%s\t%f" % (user, coord[0], coord[1], pwr))
		print "Sending beacon !"
	
	def send_position_to_station(self, coord, angle):
		self.log.writePlanePosition(self.planeID,coord, angle)
		self.sender.send("[plane]%s\t%s\t%s\t%d" % (self.planeID, coord[0], coord[1], angle))

	def send_localization_to_station(self,user, coord):
		self.log.writeLocalization(user,coord)
		self.sender.send("[user]%s\t%s\t%s" % (user, coord[0], coord[1]), retry=True)
		
	def cleanLogFile(self,log):
		""" It happens that log files generated by the planes
		are somehow corrupted (null bytes, empty lines etc...)
		This method tries to correct the format of this log file
		"""
		clean = []
		with open(log) as tsv:
			for entry in csv.reader(tsv, dialect="excel-tab"):
				if len(entry) == 0:
					continue
				if entry[0] == "[BEACON]":
					if not len(entry) == 7:
						if not len(entry) == 13:
							print "Unrecoverable line in logfile. Skipped..."
						else:
							(event0, ts0,mac0,lat0,lon0,alt0,pwr0MixEvent1,ts1,plane1,lat1,lon1,alt1,angle1) = entry
							pwr0 = float(pwr0MixEvent1.replace("[COORD]",""))
							#print "Invalid line recovered"
							frame0 = (event0,ts0,mac0,lat0,lon0,alt0,pwr0)
							frame1 = ("[COORD]", ts1, plane1, lat1,lon1,alt1,angle1)
							
							clean.append(frame0)
							clean.append(frame1)
					else:
						clean.append(entry)
		return clean
		
	def feedData(self, log, mac_filter):
		"""Load the data from the logs"""
		minPower = 100
		maxPower = 0
		

		for entry in self.cleanLogFile(log):
			if entry[0] == "[BEACON]":
				(event, ts, mac, lat, lon, alt, pwr) = entry
					
				mac = mac[1:-1]
				
				if lat == 0 or lon == 0 or pwr < 0 or not mac in mac_filter:	
					continue
	
				lat = float(lat)
				lon = float(lon)
				alt = float(alt)
				pwr = float(pwr)
				ts = int(ts)
				
				if not mac in self.clientsSignalPower:
					self.clientsSignalPower[mac] = []
				self.clientsSignalPower[mac].append((ts, lat, lon, alt, pwr, mac))
							
				maxPower = max(pwr, maxPower)
				minPower = min(pwr, minPower)
		
	def computeFromLogs(self, log, mac_filter, pwr_thresh=28, beacon_thresh=5, beacon_rpt_int=5, sort_tuple=4, output_file="flight.html"):
		"""Compute the geolocalization from the log files"""
		global app
		self.feedData(log,mac_filter)
		
		###DISABLED IN FLIGHT MODE !
		if not FLIGHT_MODE:
			if app == None:
				app = QtGui.QApplication([])
			self.gMapDisplay = GoogleMapDisplay(46.518550, 6.562460, zoom=18, output_file=output_file)
		############################
		
		lastGPS = None
		
		for user in mac_filter:
			guess = self.localize_user(user, pwr_thresh, beacon_thresh, beacon_rpt_int, sort_tuple)
			refPosition = GPSPosition(mac_filter[user][0], mac_filter[user][1])

			###DISABLED IN FLIGHT MODE !
			if not FLIGHT_MODE:
				self.gMapDisplay.addLabel(guess[0], guess[1], text=user,
						 fontFamily='sans-serif',fontSize=18,
						 fontColor='#00ff00', strokeWeight=8,
						 strokeColor='#00ff00', align='center',
						 marker=True)	
			##################################
	 
			error = GPSUtil.haversine_meter(GPSPosition(guess[0], guess[1]),refPosition)
			#print "Accuracy of %s : %fm." % (user, error)
		
		###DISABLED IN FLIGHT MODE !
		if not FLIGHT_MODE:
			for (lat,lon) in mac_filter.values():
				self.gMapDisplay.addPoint(lat, lon, radius=5, fillOpacity=1.0, fillColor='#000000', strokeColor='#0F000F')
			self.gMapDisplay.drawMap()
		##################################
		
		return error
	
	def main(self):
		if len(sys.argv) == 2:
			computeFromLogs(sys.argv[1])
		elif len(sys.argv) == 4:
			self.planeID = sys.argv[1]
			iface = sys.argv[2]
			self.logfile = sys.argv[3]
			self.log = Log(self.logfile)
			
			#TCP sender for communication with base station
			self.sender = TCPSender()
			self.sender.start()
			
			#Thread responsible for reading GPS coordinates
			self.t = Thread(target=self.readSTDIN, args = ())
			self.t.start()
			
			self.receiver = Thread(target=self.readRoutingInstructions, args = ())
			self.receiver.start()
			
			sniff(iface=iface,prn=self.trackClients,store=0)
		else:
			print "Invalid arguments"
			print "\tUsage live mode : ./PlaneSniffer <planeID> <interface> <logfile>"
			print "\tUsage replay mode : ./PlaneSniffer <logfile>"
		
	def trackClients(self, p):
		"""Listen for probe requests/response in the network"""
		
		#We're only concerned by probe request packets
		#Also, sometime, addr2 is NoneType (don't know why actually)
		#p.type = 0 -> management frame
		if not p.haslayer(Dot11) or p.addr2 is None :
			return
			
		#Ensure that this is a client
		if p.type == 0 and p.subtype in (0,2,4):
			#Signal strength
			#if not p.addr2 == 'c4:88:e5:24:3d:83':
				#return
			sig_str = 100-(256-ord(p.notdecoded[-4:-3]))
			self.send_beacon_to_station(p.addr2, self.coord, sig_str)
			t = Thread(target=self.send_beacon_to_station, args = (p.addr2,self.coord,sig_str))
			t.start()
			self.log.writeBeacon(p.addr2, self.coord, sig_str)
			if not p.addr2 in self.clientsSignalPower:
				self.clientsSignalPower[p.addr2] = []
			self.clientsSignalPower[p.addr2].append((self.log.ts(), self.coord[0], self.coord[1], self.coord[2], sig_str, p.addr2))
			center_of_mass = self.localize_user(p.addr2, pwr_thresh=26, beacon_thresh=26, beacon_rpt_int=5, sort_tuple=3)
			if not center_of_mass == None:
				t = Thread(target=self.send_localization_to_station, args = (p.addr2,center_of_mass))
				t.start()
				
if __name__ == "__main__":

	FLIGHT_MODE = True
	if FLIGHT_MODE :
		Sniffer().main();
	else:
		logHeader = "../logs/flightwifi-2014-06-13-flight"
		macFilter1 = {'c4:88:e5:24:3d:83' : (46.518440, 6.562774)}
		macFilter2 = {'64:b3:10:86:06:3a' : (46.518440,6.562774)}
		flightMacFilter = {4 : macFilter1, 5 : macFilter2}
		
		pwr_thresh=10
		beacon_thresh=1000
		for i in [1,2,3,4,5]:
			print "###Replaying %dth flight ###" % i
			passError = Sniffer().computeFromLogs("%s%d.log" % (logHeader,i), mac_filter=macFilter1, \
				pwr_thresh=pwr_thresh, beacon_thresh=beacon_thresh, beacon_rpt_int=5, sort_tuple=4, output_file="13june-%d.html" % i)
			print "Error : %f for pos %s" % (passError, macFilter1)
			print "############################"
		

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
