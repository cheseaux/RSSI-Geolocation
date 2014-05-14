#!/usr/bin/python
# -*- coding: utf-8 -*-

import csv
import math
import matplotlib.pyplot as plt
from GoogleMapDisplay import *
from PyQt4 import QtCore, QtGui, QtWebKit
from PyQt4.QtCore import *
from plot3D import *
import sys
from itertools import combinations
import collections


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
		self.angle = angl
		
class Numpy():
	
	@staticmethod
	def subtraction(a,b):
		return [a - b for a, b in zip(a, b)]
		
	@staticmethod
	def division(a,divisor):
		return [x/divisor for x in a]
		
	@staticmethod
	def norm(a):
		return math.sqrt(Numpy.dot(a,a))
	
	@staticmethod
	def dot(a,b):
		return sum(p*q for p,q in zip(a, b))
	
	@staticmethod	
	def times(a,factor):
		return [i * factor for i in a]
	
	@staticmethod	
	def cross(a, b):
		return [a[1]*b[2] - a[2]*b[1],
			a[2]*b[0] - a[0]*b[2],
			a[0]*b[1] - a[1]*b[0]]
			
	@staticmethod		
	def add(a,b):
		return [i + j for i,j in zip(a,b)]

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
	def angleBetweenCoords(gps1,gps2):
		dy = gps2.lat - gps1.lat
		dx = math.cos(math.pi/180*gps1.lat)*(gps2.lon - gps1.lon)
		return math.degrees(math.atan2(dy, dx))
		
	@staticmethod
	def weighted_sum(values, weights):
		res = 0
		totalWeight = sum(weights)
		for i in range(len(values)):
			res += values[i] * weights[i] / totalWeight
		return res

if __name__ == '__main__':
			 
	macFilter = {'c4:88:e5:24:3d:83' : (46.5193650, 6.5608350),
				 '18:e7:f4:fc:4e:1a' : (46.51855, 6.5602),
				 '64:b3:10:86:06:3a' : (46.51855, 6.5602)}				 

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

	with open('../res/flight_3rounds.log') as tsv:
		for (mac, lat, lon, alt, pwr) in csv.reader(tsv, dialect="excel-tab"):
			mac = mac[1:-1]
			if lat[1:-1] == 0 or lon[1:-1] == 0 \
				or float(pwr) < 0  \
				or not mac in macFilter:	
				continue

			lat = float(lat[1:-1])
			lon = float(lon[1:-1])
			alt = float(alt[1:-1])
			pwr = float(pwr)
			
			#gMapDisplay.addPoint(lat, lon, radius=2, fillOpacity=1.0, fillColor='#FFFF00', strokeColor='#0F000F')
	
					
			minPower = min(pwr, minPower)
			maxPower = max(pwr, maxPower)
			
			refPosition = GPSPosition(macFilter[mac][0], macFilter[mac][1])
			current = GPSPosition(lat, lon)
			dist = GPSUtil.haversine_meter(refPosition, current)
			
			#if not pwr in powerToDist:
				#powerToDist[pwr] = []
			
			#powerToDist[pwr].append(dist)
			#continue
			
			if not mac in samples:
				samples[mac] = []
			
			samples[mac].append((lat, lon, alt, pwr, mac))

	#3D plot of pwr,dist,angl
	#(x,y,z) = zip(*triplet)
	#plot3D().plot(x[1:],y[1:],z[1:])
	#gMapDisplay.addPoints(gMapsCoordinate)


	#for pwr in powerToDist:
		#powerToDist[pwr] = sum(powerToDist[pwr])/len(powerToDist[pwr])
	
	#a = collections.OrderedDict(sorted(powerToDist.items()))
	##xs, ys=zip(*((int(x), k) for k in a for x in a[k]))
	#plt.plot(a.keys(), a.values(), 'ro')
	#plt.show()
	
	
	#print "Max/Min = %d,%d" % (maxPower, minPower)

	for user in macFilter:
			
		# Sort tuples by power and remove duplicates
		usr = list(set(samples[user]))
		usr.sort(key=lambda tup: tup[3], reverse=True)
		usr = GPSUtil.remove_duplicate_GPS(usr)
		usr = [(lat,lon,alt,pwr,mac) for (lat,lon,alt,pwr,mac) in usr if pwr > 20]
		
		#for i in xrange(3,len(usr)):	
		allLat = 0
		allLon = 0	 	
		
		pwrs = []		
		for (lat,lon,alt,pwr,mac) in usr[0:len(usr)]:	
		
			pwr = (pwr/100)**2
			pwrs.append(pwr)
			
			allLat += pwr * lat
			allLon += pwr * lon
			
		allLat = allLat / sum(pwrs)
		allLon = allLon / sum(pwrs)		
			
		gMapDisplay.addLabel(allLat, allLon, text=user)
		error = GPSUtil.haversine_meter(GPSPosition(allLat, allLon),refPosition)
		print "Accuracy : %s (%d samples): %fm." % (user, len(usr), error)
	
	for (lat,lon) in macFilter.values():
		gMapDisplay.addPoint(lat, lon, radius=5, fillOpacity=1.0, fillColor='#000000', strokeColor='#0F000F')

	gMapDisplay.drawMap()
	gMapDisplay.show()
	sys.exit(app.exec_())

