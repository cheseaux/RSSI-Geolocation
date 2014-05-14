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
	
	#Slightly adapted from
	#http://gis.stackexchange.com/questions/66/trilateration-using-3-latitude-and-longitude-points-and-3-distances
	@staticmethod
	def trilateration(LatA, LonA, DistA, LatB, LonB, DistB, LatC, LonC, DistC):
		
		earthR = 6371
		P1 = GPSUtil.gpsToCartesian(LatA,LonA)
		P2 = GPSUtil.gpsToCartesian(LatB,LonB)
		P3 = GPSUtil.gpsToCartesian(LatC,LonC)

		#print [LatA,LonA]
		#print [LatB,LonB]
		#print [LatC,LonC]

		#print P1
		#print P2
		#print P3

		#from wikipedia
		#transform to get circle 1 at origin
		#transform to get circle 2 on x axis
		
		p2Minusp1 = Numpy.subtraction(P2,P1)
		p3MinusP1 = Numpy.subtraction(P3,P1)
		
		ex = Numpy.division(p2Minusp1, Numpy.norm(p2Minusp1))
		i = Numpy.dot(ex, p3MinusP1)
		iTimesEx = Numpy.times(ex,i)
		
		ey = Numpy.division(Numpy.subtraction(p3MinusP1,iTimesEx),Numpy.norm(Numpy.subtraction(p3MinusP1, iTimesEx)))
		ez = Numpy.cross(ex, ey)
		d = Numpy.norm(p2Minusp1)
		j = Numpy.dot(ey, p3MinusP1)

		#from wikipedia
		#plug and chug using above values
		x = (DistA**2 - DistB**2 + d**2) / (2 * d)
		y = (DistA**2 - DistC**2 + i**2 + j**2) / (2 * j) - (i / j) * x


		# only one case shown here
		if (DistA**2 - x**2 - y**2) < 0:
			raise Exception("No solutions")
		
		z = math.sqrt(DistA**2 - x**2 - y**2)

		#triPt is an array with ECEF x,y,z of trilateration point
		xex = Numpy.times(ex,x)
		yey = Numpy.times(ey,y)
		zez = Numpy.times(ez,z)
		
		p1xex = Numpy.add(P1, xex)
		yz = Numpy.add(yey,zez)
		
		triPt = Numpy.add(p1xex,yz)

		#convert back to lat/long from ECEF
		#convert to degrees
		lat = math.degrees(math.asin(triPt[2] / earthR))
		lon = math.degrees(math.atan2(triPt[1], triPt[0]))

		return lat, lon

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
				 
	#macFilter = {'64:b3:10:86:06:3a' : (46.51855, 6.5602)}				 

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

	for user in samples:
		if len(samples[user]) < 15:
			continue
			
		# Sort tuples by power and remove duplicates
		usr = list(set(samples[user]))
		usr.sort(key=lambda tup: tup[3], reverse=True)
		usr = GPSUtil.remove_duplicate_GPS(usr)
		
		if len(usr) == 0:
			continue
		
		for i in xrange(4,15):	
			allLat = 0
			allLon = 0	 
			N = 0
			
			lats = []
			lons = []
			pwrs = []
			
			for (pos1,pos2,pos3) in combinations(usr[0:i],3):
				(lat1, lon1, alt1, pwr1, mac1) = pos1
				(lat2, lon2, alt2, pwr2, mac2) = pos2
				(lat3, lon3, alt3, pwr3, mac3) = pos3
	
	
				pwr1 = (pwr1/100)**2
				pwr2 = (pwr3/100)**2
				pwr3 = (pwr3/100)**2
				
				p1 = GPSPosition(lat1,lon1)
				p2 = GPSPosition(lat2,lon2)
				p3 = GPSPosition(lat3,lon3)
				
				b = GPSUtil.haversine_meter(p1,p2)
				c = GPSUtil.haversine_meter(p2,p3)
				a = GPSUtil.haversine_meter(p1,p3)
				
				s = (a+b+c)/2
				area = math.sqrt(s*(s-a)*(s-b)*(s-c))
				
				if area < 25:
					continue
				
				#print "Area : %f m²" % area
				
				#gMapDisplay.addPoint(lat1, lon1, radius=3, fillOpacity=1.0, fillColor=macColor[mac1], strokeColor='#0F000F')
				#gMapDisplay.addPoint(lat2, lon2, radius=3, fillOpacity=1.0, fillColor=macColor[mac2], strokeColor='#0F000F')
				#gMapDisplay.addPoint(lat3, lon3, radius=3, fillOpacity=1.0, fillColor=macColor[mac3], strokeColor='#0F000F')
				
				sumOfSignal = pwr1 + pwr2 + pwr3
				
				lat = (pwr1 * lat1 + pwr2 * lat2 + pwr3 * lat3)/sumOfSignal
				lon = (pwr1 * lon1 + pwr2 * lon2 + pwr3 * lon3)/sumOfSignal
				
				
				#gMapDisplay.addPoint(lat, lon, radius=5, fillOpacity=0.1, fillColor='#FFFF00', strokeColor='#0F000F')
							
				##A = a**2
				##B = b**2
				##C = c**2
				
				##pos1dx = (A+B-C)/2
				##pos2dx = (B-A+C)/2
				##pos3dx = (A-B+C)/2		
			
				#norm = 100
				
				#pwr1 = norm / pwr1
				#pwr2 = norm / pwr2
				#pwr3 = norm / pwr3
				
				#delta = 2
				##normalization = (pwr1+pwr2+pwr3)/1000 #Just ensure that the spheres intersect (could be anything > ~10)
			
				#computed = False
				
				#while not computed:
					#try:
						#(lat,lon) = GPSUtil.trilateration(lat1,lon1,pwr1,\
										#lat2,lon2,pwr2,lat3,lon3,pwr3)
						#computed = True
						#break
	
					#except Exception:
						##print "failed, trying to augment"
						#pwr1 *= delta
						#pwr2 *= delta
						#pwr3 *= delta
						#computed = False
				
	
				N += 1
					
				allLat += lat
				allLon += lon
			
			allLat /= N
			allLon /= N
			
			gMapDisplay.addLabel(allLat, allLon, text=user)	
			error = GPSUtil.haversine_meter(GPSPosition(allLat, allLon),refPosition)
			print "%d : Accuracy : %s (%d samples): %fm. with %d trilateration" % (i,user,len(usr), error, N)
		
	for (lat,lon) in macFilter.values():
		gMapDisplay.addPoint(lat, lon, radius=5, fillOpacity=1.0, fillColor='#000000', strokeColor='#0F000F')

	gMapDisplay.drawMap()
	gMapDisplay.show()
	sys.exit(app.exec_())

