#!/usr/bin/env python

import math

class GPSPosition():
	def __init__(self, lat, lon):
		self.lon = lon
		self.lat = lat
		
	def weighted_sum(self, pos, weight):
		lon = (self.lon + pos.lon) * weight
		lat = (self.lat + pos.lat) * weight
		return GPSPosition(lat,lon)

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
	def remove_duplicate_GPS(log, interval=10):
		###Pick the most powerful beacon frame in small time interval
		
		clean = [] 
		lastTS = {}
		lastPWR = {}
		for (ts,lat, lon, alt, pwr, mac) in log:
			clean.append((lat, lon, alt, pwr, mac))
			continue
			
			
			#####
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
		
	
