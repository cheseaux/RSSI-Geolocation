#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = "Jonathan Cheseaux"
__copyright__ = "Copyright 2014"
__credits__ = ["Jonathan Cheseaux", "Stefano Rosati", "Karol Kruzelecki"]
__license__ = "MIT"
__email__ = "cheseauxjonathan@gmail.com"

import math

class GPSPosition():
	"""This class represent a GPS position (latitude, longitude)"""
	def __init__(self, lat, lon):
		self.lon = lon
		self.lat = lat
		
	def weighted_sum(self, pos, weight):
		"""
		Compute the weighted sum (vector) between the GPS 
		position 'pos' and the current GPS position.
		"""
		lon = (self.lon + pos.lon) * weight
		lat = (self.lat + pos.lat) * weight
		return GPSPosition(lat,lon)
		
	def equals(self, other):
		"""Override equals method"""
		return self.lat == other.lat and self.lon == other.lon

class GPSUtil():
	"""
	This utility class contains static method allowing GPS coordinates
	manipulation, such as converting them to the cartesian coordinates
	system, compute the distance between two points , etc.
	"""
	
	@staticmethod
	def gpsToCartesian(lat,lon):
		"""Not used anymore, convert gps to cartesian coordinates """
		earthR = 6371
		x = earthR *(math.cos(math.radians(lat)) * math.cos(math.radians(lon)))
		y = earthR *(math.cos(math.radians(lat)) * math.sin(math.radians(lon)))
		z = earthR *(math.sin(math.radians(lat)))
		return [x,y,z]

	@staticmethod
	def haversine_meter(gps1, gps2):
		"""Computes the distance (in meters) between two GPS position"""
		dlong = math.radians(gps2.lon - gps1.lon);
		dlat = math.radians(gps2.lat - gps1.lat);
		a = pow(math.sin(dlat / 2.0), 2) + math.cos(math.radians(gps1.lat)) * math.cos(math.radians(gps2.lat)) * pow(math.sin(dlong / 2.0), 2);
		c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a));
		d = 6367000 * c;
		return float(d);
	
	@staticmethod
	def remove_lonely_points(log, min_dist=50):
		"""
		Remove points that are isolated (whose closest
		neighboor is located further away than the min_dist parameter.
		"""
		return log
		result = []
		for (lat0, lon0, alt0, pwr0, mac0) in log:
			gps0 = GPSPosition(lat0,lon0)
			avg_dist = 0
			alone = True
			for (lat1, lon1, alt1, pwr1, mac1) in log:
				gps1 = GPSPosition(lat1,lon1)
				if (gps0.equals(gps1)):
					continue
				
				avg_dist += GPSUtil.haversine_meter(gps0,gps1)
			print "Avg dist of %f : %f" % (pwr0,avg_dist)
		return result
		
	@staticmethod
	def remove_duplicate_GPS(log, interval=5):
		"""
		Group beacon frames received during the same time interval
		and remove the lowest powered beacon frame form that group.
		It didn't change much the accuracy, so now this method only
		remove the timestamp from each entry of the log.
		"""
		
		clean = [] 
		lastTS = {}
		lastPWR = {}
		for (ts,lat, lon, alt, pwr, mac) in log:
			clean.append((lat,lon,alt,pwr,mac))
			continue
			#### BELOW IS NOT EXECUTED #####
			if mac in lastTS:
				diff = abs(lastTS[mac] - ts)
				if diff < interval * 1000.0: #seconds
					if mac in lastPWR:
						#print "Skipped MAC=%r, TS=%d, PWR=%f, against TS=%d" % (mac,ts, pwr, lastTS[mac])
						lastPWR[mac].append(pwr)
						continue
					else:
						lastPWR[mac] = [pwr]
				else:
					if mac in lastPWR:
						#pwr = sum(lastPWR[mac])/len(lastPWR[mac])
						pwr = max(lastPWR[mac])
						clean.append((lat, lon, alt, pwr, mac))
						lastTS[mac] = ts
						lastPWR[mac] = [pwr]
			else:
				lastTS[mac] = ts
		return clean
		
	@staticmethod
	def angleBetweenCoords(lat1,lon1,lat2,lon2):
		"""Computes the angle between two points"""
		dy = lat2 - lat1
		dx = math.cos(math.pi/180*lat1)*(lon2 - lon1)
		return math.degrees(math.atan2(dy, dx))
		
	@staticmethod
	def weighted_sum(values, weights):
		"""Computes the weigthed sum"""
		res = 0
		totalWeight = sum(weights)
		for i in range(len(values)):
			res += values[i] * weights[i] / totalWeight
		return res
		
	
