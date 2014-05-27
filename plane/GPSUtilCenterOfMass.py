#!/usr/bin/python
# -*- coding: utf-8 -*-

import csv
import math
import matplotlib.pyplot as plt
from GoogleMapDisplay import *
from PyQt4 import QtCore, QtGui, QtWebKit
from PyQt4.QtCore import *
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
			 
	macFilter = {'c4:88:e5:24:3d:83' : (46.5193650, 6.5608350),
				 '18:e7:f4:fc:4e:1a' : (46.51855, 6.5602),
				 '64:b3:10:86:06:3a' : (46.51855, 6.5602)}	
				 
	#macFilter = {'c4:88:e5:24:3d:83' : (46.51855, 6.5602)}				 

	macColor = {'c4:88:e5:24:3d:83' : '#FF0000',
				 '18:e7:f4:fc:4e:1a' : '#00FF00',
				 '64:b3:10:86:06:3a' : '#0000FF'}
	powerToDist = {}			 
	
	minPower = 100
	maxPower = 0
	samples = {}
	app = QtGui.QApplication([])
	gMapDisplay = GoogleMapDisplay(46.51856613, 6.560246944, zoom=20)
	triplet = []
	lastGPS = None

	with open('log-sniffer-second.log') as tsv:
		for entry in csv.reader(tsv, dialect="excel-tab"):
			if entry[0] == "[COORD]":
				(event, ts, mac, lat, lon, alt, pwr) = entry
			#(mac,lat,lon,alt,pwr) = entry
				mac = mac[1:-1]
				if lat == 0 or lon == 0 \
					or float(pwr) < 0 \
					or not mac in macFilter:	
					continue
	
				lat = float(lat)
				lon = float(lon)
				alt = float(alt)
				pwr = float(pwr)
				
				rssi_max = 60
				#sig_str assumed to be percentage (atheros) -> pwr / pwrmax * 100.0
				pwr = int(pwr/100.0 * rssi_max - 95)			
				#pwr = math.log(1.0/sig_str_dbm**2)	
						
				minPower = min(pwr, minPower)
				maxPower = max(pwr, maxPower)
				
				refPosition = GPSPosition(macFilter[mac][0], macFilter[mac][1])
				current = GPSPosition(lat, lon)
				dist = GPSUtil.haversine_meter(refPosition, current)
				
				if not pwr in powerToDist:
					powerToDist[pwr] = []
				
				powerToDist[pwr].append(dist)
				#continue
				
				if not mac in samples:
					samples[mac] = []
				
				samples[mac].append((lat, lon, alt, pwr, mac))

	#3D plot of pwr,dist,angl
	#(x,y,z) = zip(*triplet)
	#plot3D().plot(x[1:],y[1:],z[1:])
	#gMapDisplay.addPoints(gMapsCoordinate)
	
	#print powerToDist
	#plt.plot(*zip(*sorted(powerToDist.items())))

	#print powerToDist
	#for k, v in powerToDist.iteritems():
		#x = [k] * len(v)
		#y = v
		#plt.plot(x, y)
	#plt.show()
	
	
	
	
	print "Max/Min = %d,%d" % (maxPower, minPower)
	
	for user in samples:
		usr = list(set(samples[user]))
		usr.sort(key=lambda tup: tup[3], reverse=True)
		usr = GPSUtil.remove_duplicate_GPS(usr)
		#usr = [(lat,lon,alt,pwr,mac) for (lat,lon,alt,pwr,mac) in usr if pwr >= 0]
			
		#for i in xrange(1,len(usr)):
		# Sort tuples by power and remove duplicates
		
		print "Before : ",
		print len(usr)
		usr = GPSUtil.remove_neighboors(usr, threshold=0)
		print "After : ",
		print len(usr)
		
		#for i in xrange(3,len(usr)):	
		allLat = 0
		allLon = 0	 	

		pwrs = []		
		for (lat,lon,alt,pwr,mac) in usr:	
			
			
			#sig_str_dbm = -2*math.log(sig_str_dbm)
			pwrs.append(pwr)
			gMapDisplay.addLabel(lat, lon, text="%f\t%f" % (pwr,alt))
			allLat += pwr * lat
			allLon += pwr * lon
			
		allLat = allLat / sum(pwrs)
		allLon = allLon / sum(pwrs)		
		gMapDisplay.addLabel(allLat, allLon, text=user,
				 fontFamily='sans-serif',fontSize=18,
				 fontColor='#00ff00', strokeWeight=8,
				 strokeColor='#00ff00', align='center',
				 marker=True)	
		
		error = GPSUtil.haversine_meter(GPSPosition(allLat, allLon),refPosition)
		print "Accuracy : %s (%d samples): %fm." % (user, len(usr), error)
	
	for (lat,lon) in macFilter.values():
		gMapDisplay.addPoint(lat, lon, radius=5, fillOpacity=1.0, fillColor='#000000', strokeColor='#0F000F')
	
	gMapDisplay.drawMap()
	#gMapDisplay.show()
	#sys.exit(app.exec_())

