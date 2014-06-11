#!/usr/bin/python
# -*- coding: utf-8 -*-

import csv
import math
import matplotlib.pyplot as plt
from GoogleMapDisplay import *
import sys
from itertools import combinations
import collections
from GPSUtil import *


class GPSPosition():
	def __init__(self, lat, lon):
		self.lon = lon
		self.lat = lat
		
	def weighted_sum(self, pos, weight):
		lon = (self.lon + pos.lon) * weight
		lat = (self.lat + pos.lat) * weight
		return GPSPosition(lat,lon)

class Triplet():
	def __init__(self,pwr,dist,angle):
		self.pwr = pwr
		self.dist = dist
		self.angle = angle



if __name__ == '__main__':
			 
	#macFilter = {'c4:88:e5:24:3d:83' : (46.5193650, 6.5608350),
				 #'18:e7:f4:fc:4e:1a' : (46.51855, 6.5602),
				 #'64:b3:10:86:06:3a' : (46.51855, 6.5602)}	
		
	#macFilter = {'64:b3:10:86:06:3a' : (46.51855, 6.5602)}		
				 
	macFilter = {'c4:88:e5:24:3d:83' : (46.518594,6.562449)}				 

	macColor = {'c4:88:e5:24:3d:83' : '#FF0000',
				 '18:e7:f4:fc:4e:1a' : '#00FF00',
				 '64:b3:10:86:06:3a' : '#0000FF'}

	
	minPower = -95
	maxPower = -35
	samples = {}
	app = QtGui.QApplication([])
	gMapDisplay = GoogleMapDisplay(46.51856613, 6.560246944, zoom=20)
	triplet = []
	lastGPS = None

	#with open('/media/cheseaux/PENDRIVE/all-files/flightwifi-2014-06-10-flight2.log') as tsv:
	with open('stefano.txt') as tsv:
		for entry in csv.reader(tsv, dialect="excel-tab"):
			if entry[0] == "[BEACON]":
				(event, ts, mac, lat, lon, alt, pwr) = entry
			#(mac,lat,lon,alt,pwr) = entry
				mac = mac[1:-1]
				if lat == 0 or lon == 0 \
					or pwr < 0 \
					or not mac in macFilter:	
					continue
	
				lat = float(lat)
				lon = float(lon)
				alt = float(alt)
				pwr = float(pwr)
				ts = int(ts)
				
				current = GPSPosition(lat, lon)
				
				if lastGPS:
					dist = GPSUtil.haversine_meter(lastGPS, current)
					print "Distance : ",
					print  dist
				lastGPS = current
			
				rssi_max = 60
				##sig_str assumed to be percentage (atheros) -> pwr / pwrmax * 100.0
				#pwr = int(pwr/100.0 * rssi_max - 95)			
				##pwr = math.log(1.0/sig_str_dbm**2)	
		
				maxPower = min(pwr, maxPower)
				minPower = max(pwr, minPower)
				
				refPosition = GPSPosition(macFilter[mac][0], macFilter[mac][1])
				
				
				if not mac in samples:
					samples[mac] = []
				
				samples[mac].append((ts,lat, lon, alt, pwr, mac))

	print "Max/Min = %d,%d" % (minPower, maxPower)
	
	
	for user in samples:
		#usr = list(set(samples[user]))
		usr = samples[user]
		usr.sort(key=lambda tup: tup[0], reverse=False)
		print "Before duplicate removal ",
		print len(usr)
		usr = GPSUtil.remove_duplicate_GPS(usr,1)
		print "After duplicate removal ",
		print len(usr)
		usr.sort(key=lambda tup: tup[4], reverse=False)
		
		
		totalError = 0
		for i in xrange(1,len(usr)):	
			#for i in xrange(3,len(usr)):	
			allLat = 0
			allLon = 0	 	
	
			pwrs = []
			dists = []
					
			for (lat,lon,alt,pwr,mac) in usr[0:i]:	
				print pwr
				#sig_str_dbm = -2*math.log(sig_str_dbm)
				pwrs.append(pwr)
				gMapDisplay.addLabel(lat, lon, text="%f\t%f" % (pwr,alt))
				allLat += pwr * lat
				allLon += pwr * lon
				
				current = GPSPosition(lat, lon)
				dist = GPSUtil.haversine_meter(refPosition, current)
				dists.append(dist)
		
				
			allLat = allLat / sum(pwrs)
			allLon = allLon / sum(pwrs)		
			gMapDisplay.addLabel(allLat, allLon, text=user,
					 fontFamily='sans-serif',fontSize=18,
					 fontColor='#00ff00', strokeWeight=8,
					 strokeColor='#00ff00', align='center',
					 marker=True)	
	 
			#Plot
			#plt.scatter(pwrs,dists)
			#plt.show()
			error = GPSUtil.haversine_meter(GPSPosition(allLat, allLon),refPosition)
			print "Accuracy : %s (%d %%samples): %fm." % (user, float(i)/len(usr)*100.0, error)
			totalError += error
		avg = totalError/i
		print "Erreur moyenne : %f" % (avg)
	for (lat,lon) in macFilter.values():
		gMapDisplay.addPoint(lat, lon, radius=5, fillOpacity=1.0, fillColor='#000000', strokeColor='#0F000F')
	
	gMapDisplay.drawMap()
	#gMapDisplay.show()
	#sys.exit(app.exec_())

