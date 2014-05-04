#!/usr/bin/python
# -*- coding: utf-8 -*-

import csv
from math import *
from numpy import *
import matplotlib.pyplot as plt
from GoogleMapDisplay import *
from PyQt4 import QtCore, QtGui, QtWebKit
from PyQt4.QtCore import *
from plot3D import *
import sys
from itertools import permutations


class GPSPosition():
	def __init__(self, lat, lon):
		self.lon = lon
		self.lat = lat

class Triplet():
	def __init__(self,pwr,dist,angle):
		self.pwr = pwr
		self.dist = dist
		self.angle = angle

class GPSUtil():
	
	@staticmethod
	def gpsToCartesian(lat,lon):
		earthR = 6371
		x = earthR * (math.cos(math.radians(lat)) * math.cos(math.radians(lon)))
		y = earthR * (math.cos(math.radians(lat)) * math.sin(math.radians(lon)))
		z = earthR * (math.sin(math.radians(lat)))
		return [x,y,z]
	
	#Slightly adapted from
	#http://gis.stackexchange.com/questions/66/trilateration-using-3-latitude-and-longitude-points-and-3-distances
	@staticmethod
	def trilateration(LatA, LonA, DistA, LatB, LonB, DistB, LatC, LonC, DistC):
		
		earthR = 6371
		P1 = array(GPSUtil.gpsToCartesian(LatA,LonA))
		P2 = array(GPSUtil.gpsToCartesian(LatB,LonB))
		P3 = array(GPSUtil.gpsToCartesian(LatC,LonC))

		#from wikipedia
		#transform to get circle 1 at origin
		#transform to get circle 2 on x axis
		ex = (P2 - P1) / (linalg.norm(P2 - P1))
		i = dot(ex, P3 - P1)
		ey = (P3 - P1 - i * ex) / (linalg.norm(P3 - P1 - i * ex))
		ez = cross(ex, ey)
		d = linalg.norm(P2 - P1)
		j = dot(ey, P3 - P1)

		#from wikipedia
		#plug and chug using above values
		x = (pow(DistA, 2) - pow(DistB, 2) + pow(d, 2)) / (2 * d)
		y = ((pow(DistA, 2) - pow(DistC, 2) + pow(i, 2) + pow(j, 2)) / (2 * j)) - ((i / j) * x)

		# only one case shown here
		z = sqrt(abs(pow(DistA, 2) - pow(x, 2) - pow(y, 2)))

		#triPt is an array with ECEF x,y,z of trilateration point
		triPt = P1 + x * ex + y * ey + z * ez

		#convert back to lat/long from ECEF
		#convert to degrees
		lat = math.degrees(math.asin(triPt[2] / earthR))
		lon = math.degrees(math.atan2(triPt[1], triPt[0]))

		return lat, lon

	@staticmethod
	def haversine_meter(gps1, gps2):
		dlong = radians(gps2.lon - gps1.lon);
		dlat = radians(gps2.lat - gps1.lat);
		a = pow(sin(dlat / 2.0), 2) + cos(radians(gps1.lat)) * cos(radians(gps2.lat)) * pow(sin(dlong / 2.0), 2);
		c = 2 * atan2(sqrt(a), sqrt(1 - a));
		d = 6367000 * c;
		return d;
		
	@staticmethod
	def angleBetweenCoords(gps1,gps2):
		dy = gps2.lat - gps1.lat
		dx = cos(math.pi/180*gps1.lat)*(gps2.lon - gps1.lon)
		return math.degrees(atan2(dy, dx))


if __name__ == '__main__':

	samples = {}
	app = QtGui.QApplication([])
	gMapDisplay = GoogleMapDisplay(46.51856613, 6.560246944, zoom=20)
	#gMapDisplay.showPointsTriangle()
	#gMapDisplay.show()
	#minPower = 100
	#maxPower = 0
	triplet = []
	refPosition = GPSPosition(46.51855, 6.5602)
	
	
	#######IDEAS FOR THE PROJECT ###########
	# 1) interaction possible from laptop to planes ?
	#     yes : periodically send logs from each planes to the laptop
	#			-> localize people (precision increases after each period)
	#    Even if interaction not possible, use cron job and periodically send logs
	#
	# 2) possible to drive the planes ?
	#     yes : move the planes around a user to increase localization performance
	#
	# No timestamps needed, 0 orientation-pwr correlation
	# Handle mobile user ? (If user location changes, how to be aware of that)
	#  
	# 
	
	lastGPS = None

	with open('../res/smavnet.log') as tsv:
		for (mac, lat, lon, alt, pwr) in csv.reader(tsv, dialect="excel-tab"):
			lat = float(lat[1:-1])
			lon = float(lon[1:-1])
			pwr = float(pwr)
			if lat == 0.0 or lon == 0.0 or pwr < 0: #or mac != "'64:b3:10:86:06:3a'":
				continue

			#minPower = min(pwr, minPower)
			#maxPower = max(pwr, maxPower)
			current = GPSPosition(lat, lon)
			dist = GPSUtil.haversine_meter(refPosition, current)
			
			if not mac in samples:
				samples[mac] = []
			
			samples[mac].append((lat, lon, pwr))
			
			if lastGPS == None:
				triplet.append((pwr, dist, None))
			else:
				angle = GPSUtil.angleBetweenCoords(current, lastGPS)
				triplet.append((pwr,dist,angle))
			
			lastGPS = current
			
	#3D plot of pwr,dist,angl
	(x,y,z) = zip(*triplet)
	plot3D().plot(x[1:],y[1:],z[1:])
	
	
	#gMapDisplay.addPoints(gMapsCoordinate)

	for user in samples:
		# Sort tuples by power and remove duplicates
		usr = list(set(samples[user]))
		usr.sort(key=lambda tup: tup[2], reverse=True)
		
		allLat = 0
		allLon = 0	 
		N = 0
		
		for (pos1,pos2,pos3) in permutations(usr[0:3], 3):
			(lat1, lon1, pwr1) = pos1
			(lat2, lon2, pwr2) = pos2
			(lat3, lon3, pwr3) = pos3
		
			normalization = (pwr1+pwr2+pwr3)*1000 #Just ensure that the spheres intersect (could be anything > ~10)
		
			(lat,lon) = GPSUtil.trilateration(lat1,lon1,pwr1/normalization,\
								  lat2,lon2,pwr2/normalization,lat3,lon3,pwr3/normalization)
			allLat += lat
			allLon += lon
			N += 1
			
			#gMapDisplay.addPoint(lat, lon, radius=2, fillOpacity=1.0, fillColor='#FFFF00', strokeColor='#0F000F')
	
		if N == 0:
			continue
	
		gMapDisplay.addPoint(allLat/N, allLon/N, radius=max(1,len(usr)/10), fillOpacity=1, fillColor='#FF0000', strokeColor='#0F000F')
	
	
		error = GPSUtil.haversine_meter(GPSPosition(allLat/N, allLon/N),refPosition)
		print "Error : %f meters by computing %d trilateration" % (error, N)

	#Linear mapping of signal strength to circle radius
	#a = (100 - 1) / (maxPower - minPower)
	#b = 1 - minPower * a
	#c = 2.7 #correction constant

	#for (lat, lon, pwr) in samples[0:10]:
	#   gMapDisplay.addPoint(lat, lon, radius=(a * pwr + b) * c, fillOpacity=0.1, strokeColor='0x000000')
	#   gMapDisplay.addPoint(lat, lon, radius=2, fillOpacity=1, strokeColor='0x0000FF')

	gMapDisplay.addPoint(refPosition.lat, refPosition.lon, radius=1, fillOpacity=1.0, fillColor='#00FF00', strokeColor='#0F000F')
	plt.figure()
	gMapDisplay.drawMap()
	gMapDisplay.show()
	sys.exit(app.exec_())

##Bufferize distances
#count = 0
#maxVal = distances[0]
#maxValPower = signalPower[0]
#x = []
#y = []
#for i in range(0,len(distances)):
#count += 1
#if distances[i] > maxVal:
#maxVal = distances[i]
#maxValPower = signalPower[i];
#if count % 10 == 0:
#x.append(maxVal)
#y.append(maxValPower)
#maxVal = 0
#maxValPower = 0

#print "%f %d" % (distances[i], signalPower[i])

#plt.plot(x, y, 'ro')
#plt.title('Signal power to distance graph (all samples)')
#plt.ylabel('Signal power')
#plt.xlabel('Distance [m]')
#plt.show()
		
