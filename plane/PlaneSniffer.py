#!/usr/bin/env python

import os
from scapy.all import *
from threading import Thread
import math
import time
import sys
from TCPSender import *
from GPSUtil import *

#Comment below import when running from the gumstix:
#import csv
#from GoogleMapDisplay import *

FLIGHT_MODE = True

if not FLIGHT_MODE:
	app = None	


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
			
	def reduceSearchArea(self, target='c4:88:e5:24:3d:83'):
		while True:
			
			(lat,lon) = self.localize_user(target,30,100)
			self.writeFileForPilot(lat,lon,self.search_radius)
			print "Reducing search area to circle : %f,%f radius : %f" % (lat,lon,self.search_radius)
			self.search_radius = self.search_radius * 0.75 #reduce radius for next iteration
			if (self.search_radius < 20.0):
				break
				
			time.sleep(1*60*2)
			
			
	def readRoutingInstructions(self):
		while True:
			instructions = self.sender.receive()
			if not instructions == None:
				radius = 400 #meters
				(event, neLat,neLng,swLat,swLng) = instructions
				print "Received new coordinates of flight ! %r %r %r %r" % (neLat,neLng,swLat,swLng)
				#compute the center:
				center_x = (float(neLat) + float(swLat)) / 2.0
				center_y = (float(neLng) + float(swLng)) / 2.0
				self.writeFileForPilot(center_x,center_y,radius)
				self.t = Thread(target=self.reduceSearchArea, args = (''))
				self.t.start()
				
	def writeFileForPilot(self, center_x, center_y, radius, altitude=70):
		command = "/smavnet/gapi_sendcoordinates %f %f %f %f" % (center_x, center_y, altitude, radius)
		os.system(command)

	def compute_center_of_mass(self,samples, sort_tuple, map_pwr_func, pwr_thresh, beacon_thresh, beacon_rpt_int):
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
					self.gMapDisplay.addLabel(lat, lon, text="%f" % (pwr))
				#############################
				
				pwrs.append(pwr)
				allLat += pwr * lat
				allLon += pwr * lon
				
		if sum(pwrs) == 0:
			return None
			
		#print "Center of mass using %d samples" % (len(pwrs))
		#print "Power used : ",
		#print pwrs
		return (allLat / sum(pwrs), allLon / sum(pwrs))
	
	def localize_user(self, user, pwr_thresh, beacon_thresh, beacon_rpt_int=5, sort_tuple=3):
		samples = self.clientsSignalPower[user]
		#pwr_func = lambda x : (x/100.0)
		pwr_func = lambda x : x
		return self.compute_center_of_mass(samples=samples, sort_tuple=sort_tuple, map_pwr_func=pwr_func, pwr_thresh=pwr_thresh, beacon_thresh=beacon_thresh, beacon_rpt_int=beacon_rpt_int)
		
	
	def send_position_to_station(self, coord, angle):
		self.sender.send("[plane]%s\t%s\t%s\t%d" % (self.planeID, coord[0], coord[1], angle))
		#print "Cant send position but still wrote to log"
		self.log.writePlanePosition(self.planeID,coord, angle)

	def send_localization_to_station(self,user, coord):
		self.sender.send("[user]%s\t%s\t%s" % (user, coord[0], coord[1]))
		#print "Cant send localization but still wrote to log"
		self.log.writeLocalization(user,coord)
		
	def cleanLogFile(self,log):
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
					
		print "Max power : %f, Min power :%f" % (maxPower,minPower)
	

		
	def computeFromLogs(self, log, mac_filter, pwr_thresh=28, beacon_thresh=5, beacon_rpt_int=5, sort_tuple=4, output_file="flight.html"):
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
		#We're only concerned by probe request packets
		#Also, sometime, addr2 is NoneType (don't know why actually)
		#p.type = 0 -> management frame
		if not p.haslayer(Dot11) or p.addr2 is None :
			return
			
		#Ensure that this is a client
		if p.type == 0 and p.subtype in (0,2,4):
			#Signal strength
			sig_str = 100-(256-ord(p.notdecoded[-4:-3]))
			self.log.writeBeacon(p.addr2, self.coord, sig_str)
			if not p.addr2 in self.clientsSignalPower:
				self.clientsSignalPower[p.addr2] = []
			self.clientsSignalPower[p.addr2].append((self.log.ts(), self.coord[0], self.coord[1], self.coord[2], sig_str, p.addr2))
			center_of_mass = self.localize_user(p.addr2, pwr_thresh=28, beacon_thresh=100, beacon_rpt_int=5, sort_tuple=3)
			if not center_of_mass == None:
				self.send_localization_to_station(p.addr2,center_of_mass)
				
if __name__ == "__main__":
	
	Sniffer().main();
	
	#logHeader = "/media/cheseaux/PENDRIVE/all-files/flightwifi-2014-06-10-flight"
	#macFilter1 = {'c4:88:e5:24:3d:83' : (46.518550, 6.562460)}
	#macFilter2 = {'c4:88:e5:24:3d:83' : (46.518543,6.562807)}
	#flightMacFilters = {2:macFilter1, 4:macFilter1, 5:macFilter1, 6:macFilter2}
	
	#min_average_error = 100000.0
	#min_error = 1000000.0
	#best_param = None
	#best_min_param = None
	
	#for j in [0]:
		#for p in [1000]:
			#pwr_thresh=j
			#beacon_thresh=p
			#print j
			#print "Parameters : pwr_thresh=%d, beacon_thresh=%d" % (pwr_thresh, beacon_thresh)
			#error = []
			#for i in [2,4,5,6]:
				#print "###Replaying %dth flight ###" % i
				#passError = Sniffer().computeFromLogs("%s%d.log" % (logHeader,i), mac_filter=flightMacFilters[i], \
					#pwr_thresh=pwr_thresh, beacon_thresh=beacon_thresh, beacon_rpt_int=5, sort_tuple=4, output_file="%d.html" % i)
				#error.append(passError)
				#print "Error : %f" % passError
				#if passError < min_error:
					#min_error = passError
					#best_min_param = (pwr_thresh,beacon_thresh)
				#print "############################"
			
			#average_error = sum(error)/len(error)
			#print "Average error : %d , min avg error : %d" % (average_error, min_average_error)
			#print average_error
			#if average_error < min_average_error:
				#min_average_error = average_error
				#best_param = (pwr_thresh,beacon_thresh)
	
	#print "Minimum average error : %f%%" % (min_average_error)
	#(pwrt,beact) = best_param
	#print "With parameters : pwr_thresh=%f, beacon_thresh=%f" % (pwrt,beact)
	#print "Minimum error : %f%%" % (min_error)
	#(pwrt,beact) = best_min_param
	#print "With parameters : pwr_thresh=%f, beacon_thresh=%f" % (pwrt,beact)
	#


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
