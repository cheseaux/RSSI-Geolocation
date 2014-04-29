#!/usr/bin/python
# -*- coding: utf-8 -*-

import csv
from math import *
from numpy import *
import matplotlib.pyplot as plt
from GoogleMapDisplay import *
from PyQt4 import QtCore, QtGui, QtWebKit
from PyQt4.QtCore import *
import sys


class GPSPosition():
    def __init__(self, lat, lon):
        self.lon = lon
        self.lat = lat


class GPSUtil():


    #Slightly adapted from
    #http://gis.stackexchange.com/questions/66/trilateration-using-3-latitude-and-longitude-points-and-3-distances
    @staticmethod
    def trilateration(LatA, LonA, DistA, LatB, LonB, DistB, LatC, LonC, DistC):
        #assuming elevation = 0
        earthR = 6371

        #using authalic sphere
        #if using an ellipsoid this step is slightly different
        #Convert geodetic Lat/Long to ECEF xyz
        #   1. Convert Lat/Long to radians
        #   2. Convert Lat/Long(radians) to ECEF
        xA = earthR * (math.cos(math.radians(LatA)) * math.cos(math.radians(LonA)))
        yA = earthR * (math.cos(math.radians(LatA)) * math.sin(math.radians(LonA)))
        zA = earthR * (math.sin(math.radians(LatA)))

        xB = earthR * (math.cos(math.radians(LatB)) * math.cos(math.radians(LonB)))
        yB = earthR * (math.cos(math.radians(LatB)) * math.sin(math.radians(LonB)))
        zB = earthR * (math.sin(math.radians(LatB)))

        xC = earthR * (math.cos(math.radians(LatC)) * math.cos(math.radians(LonC)))
        yC = earthR * (math.cos(math.radians(LatC)) * math.sin(math.radians(LonC)))
        zC = earthR * (math.sin(math.radians(LatC)))

        P1 = array([xA, yA, zA])
        P2 = array([xB, yB, zB])
        P3 = array([xC, yC, zC])

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
        d2r = math.pi / 180.0
        dlong = (gps2.lon - gps1.lon) * d2r;
        dlat = (gps2.lat - gps1.lat) * d2r;
        a = pow(sin(dlat / 2.0), 2) + cos(gps1.lat * d2r) * cos(gps2.lat * d2r) * pow(sin(dlong / 2.0), 2);
        c = 2 * atan2(sqrt(a), sqrt(1 - a));
        d = 6367000 * c;
        return d;


if __name__ == '__main__':

    samples = []
    app = QtGui.QApplication([])
    gMapDisplay = GoogleMapDisplay(46.51856613, 6.560246944, zoom=16)
    #gMapDisplay.showPointsTriangle()
    #gMapDisplay.show()
    minPower = 100
    maxPower = 0

    refPosition = GPSPosition(46.51856613, 6.560246944)

    with open('../res/smavnet.log') as tsv:
        for (mac, lat, lon, alt, pwr) in csv.reader(tsv, dialect="excel-tab"):
            lat = float(lat[1:-1])
            lon = float(lon[1:-1])
            pwr = float(pwr)
            if lat == 0.0 or lon == 0.0 or pwr < 0 or mac != "'64:b3:10:86:06:3a'":
                continue

            minPower = min(pwr, minPower)
            maxPower = max(pwr, maxPower)
            current = GPSPosition(lat, lon)
            dist = GPSUtil.haversine_meter(refPosition, current)
            samples.append((lat, lon, pwr))

    #gMapDisplay.addPoints(gMapsCoordinate)
    maxPower - minPower

    # Sort tuples by power and remove duplicates
    samples = list(set(samples))
    samples.sort(key=lambda tup: tup[2], reverse=True)
    #
    (lat1, lon1, pwr1) = samples[0]
    (lat2, lon2, pwr2) = samples[1]
    (lat3, lon3, pwr3) = samples[2]

    normalization = (pwr1+pwr2+pwr3)*1000

    (lat,lon) = GPSUtil.trilateration(lat1,lon1,pwr1/normalization,\
                          lat2,lon2,pwr2/normalization,lat3,lon3,pwr3/normalization)

    gMapDisplay.addPoint(lat, lon, radius=5, fillOpacity=1.0, fillColor='#000000', strokeColor='#0F000F')

    error = GPSUtil.haversine_meter(GPSPosition(lat,lon),refPosition)
    print "Error : %d meters" % error

    #Linear mapping of signal strength to circle radius
    a = (140 - 1) / (maxPower - minPower)
    b = 1 - minPower * a

    for (lat, lon, pwr) in samples[:3]:
       gMapDisplay.addPoint(lat, lon, radius=a * pwr + b, fillOpacity=0.1, strokeColor='0x000000')



    #gMapDisplay.addPoint(46.51856613, 6.560246944, radius=5, fillColor='#000000')

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
		
