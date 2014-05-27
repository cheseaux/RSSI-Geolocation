#!/usr/bin/env python

import math
from GPSUtilCenterOfMass import *

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
	def remove_neighboors(log,threshold):
		result = GPSUtil.clusterize(log, threshold)
		unchanged = False
		lastLen = len(result)
		while not unchanged:
			result = GPSUtil.clusterize(result,threshold)
			unchanged = (len(result) == lastLen)
			lastLen = len(result)
		return result
		
	@staticmethod	
	def clusterize(log,threshold):
		result = []
		watched = [] #Keep track of entry already seen (to avoid duplicates)
		for entry in log:
			if entry in watched:
				continue
			neighboors, maxBeacon = GPSUtil.get_neighboors_and_max(entry,log,threshold)
			watched.extend(neighboors)
			result.append(maxBeacon)
		return result
				
	@staticmethod			
	def get_neighboors_and_max(entry,log, threshold):
		(lat0,lon0,alt0, pwr0, mac0) = entry
		refPos = GPSPosition(lat0,lon0)
		result = []
		maxEntry = entry
		maxPwr = pwr0
		for (lat,lon,alt, pwr, mac) in log:
			targetPos = GPSPosition(lat,lon)
			dist = GPSUtil.haversine_meter(refPos,targetPos)
			if dist < threshold:
				result.append((lat,lon,alt,pwr,mac))
				if pwr > maxPwr:
					maxEntry = (lat,lon,alt,pwr,mac)
					maxPwr = pwr
		return result, maxEntry
	
	@staticmethod
	def remove_duplicate_GPS(log):
		return log
		#s = set()
		#topN = []
		#for (lat,lon,alt, pwr, mac) in log:
			#if not s.intersection((lat,lon, mac)):
				#s.update((lat,lon, mac))
				#topN.append((lat,lon,alt, pwr, mac))
		#return topN
		
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
		
	@staticmethod
	def compute_center_of_mass(samples, map_pwr_func, pwr_thresh, beacon_thresh):
		usr = list(set(samples))
		usr.sort(key=lambda tup: tup[3], reverse=True)
		usr = GPSUtil.remove_duplicate_GPS(usr)
		
		allLat = 0
		allLon = 0	 	
		
		pwrs = []		
		for (lat,lon,alt,pwr,mac) in usr[0:min(len(usr),beacon_thresh)]:	
			if pwr >= pwr_thresh:
				pwr = map_pwr_func(pwr)
				pwrs.append(pwr)
				allLat += pwr * lat
				allLon += pwr * lon
				
		if sum(pwrs) == 0:
			return None
		
		return (allLat / sum(pwrs), allLon / sum(pwrs))
