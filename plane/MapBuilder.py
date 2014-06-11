#!/usr/bin/python
# -*- coding: utf-8 -*-

import math


class Drawable():
	def __init__(self, lat, lon, \
				 fillColor="#00FF00", \
				 fillOpacity=1.0, \
				 strokeColor="#FF0000", \
				 strokeOpacity=1.0, \
				 strokeWeight=1):
		self.lat = lat
		self.lon = lon
		self.clickable = 'false'
		self.geodesic = 'true'
		self.fillColor = fillColor
		self.fillOpacity = fillOpacity
		self.strokeColor = strokeColor
		self.strokeOpacity = strokeOpacity
		self.strokeWeight = strokeWeight

class MapLabel():
	
	def __init__(self, lat, lon, text,
					fontFamily='sans-serif',
					fontSize=12,
					fontColor='#000000',
					strokeWeight=4,
					strokeColor='#ffffff',
					align='center',
					marker=True):
		self.position = "new google.maps.LatLng(%f, %f)" % (lat,lon)
		self.fontFamily=fontColor
		self.fontSize = fontSize
		self.strokeWeight=strokeWeight
		self.strokeColor=strokeColor
		self.align = align
		self.text = text
		self.index = 0
		self.marker = marker

class Circle(Drawable):
	def __init__(self, lat, lon,
				 fillColor="#00FF00", \
				 fillOpacity=1.0, \
				 strokeColor="#FF0000", \
				 strokeOpacity=1.0, \
				 strokeWeight=1, \
				 radius=10):
		Drawable.__init__(self,lat, lon, fillColor, fillOpacity, strokeColor, strokeOpacity, strokeWeight)
		self.radius = radius


class MapBuilder:
	RESOLUTION = 180

	def __init__(self, centerLat, centerLng, zoom, mapType='SATELLITE'):
		self.center = (float(centerLat), float(centerLng))
		self.zoom = int(zoom)
		self.points = []
		self.mapType = mapType
		self.circles = []
		self.texts = []
		self.coloricon = 'http://chart.apis.google.com/chart?cht=mm&chs=12x16&chco=FFFFFF,XXXXXX,000000&ext=.png'

	def clear(self):
		self.points = []
		self.circles = []
		self.texts = []

	#create the html file which inlcude one google map and all points and paths
	def draw(self, htmlfile):
		f = open(htmlfile, 'w')
		f.write('<html>\n')
		f.write('<head>\n')
		f.write('<meta name="viewport" content="initial-scale=1.0, user-scalable=no" />\n')
		f.write('<meta http-equiv="content-type" content="text/html; charset=UTF-8"/>\n')
		f.write('<title>Google Maps - pygmaps </title>\n')
		f.write('<script type="text/javascript" src="http://maps.google.com/maps/api/js?sensor=false"></script>\n')
		f.write('<script type="text/javascript" src="maplabel-compiled.js"></script>')
		f.write('<script type="text/javascript">\n')
		f.write('\tfunction initialize() {\n')
		self.drawmap(f)
		self.drawCircles(f)
		self.drawTexts(f)
		f.write('\t}\n')
		f.write('</script>\n')
		f.write('</head>\n')
		f.write('<body style="margin:0px; padding:0px;" onload="initialize()">\n')
		f.write('\t<div id="map_canvas" style="width: 100%; height: 100%;"></div>\n')
		f.write('</body>\n')
		f.write('</html>\n')
		f.close()

	def drawCircles(self, f):
		for circ in self.circles:
			self.drawCircle(f, circ)
			
	def drawTexts(self,f):
		for label in self.texts:
			self.drawText(f,label)

	def drawmap(self, f):
		f.write('\t\tvar centerlatlng = new google.maps.LatLng(%f, %f);\n' % (self.center[0], self.center[1]))
		f.write('\t\tvar myOptions = {\n')
		f.write('\t\t\ttilt:0,\n')
		f.write('\t\t\tzoom: %d,\n' % (self.zoom))
		f.write('\t\t\tcenter: centerlatlng,\n')
		f.write('\t\t\tmapTypeId: google.maps.MapTypeId.%s\n' % self.mapType)
		f.write('\t\t};\n')
		f.write('\t\tvar map = new google.maps.Map(document.getElementById("map_canvas"), myOptions);\n')
		f.write('\n')

	def drawText(self,f,mapLabel):
		f.write('var mapLabel = new MapLabel({\n')
		f.write('\ttext: "%s",\n' % mapLabel.text)
		f.write('\tposition: %s,\n' % (mapLabel.position))
		f.write('\tmap: map,\n')
		f.write('\tfontSize: %d,\n' % mapLabel.fontSize)
		f.write('\talign: "%s"\n' % mapLabel.align)
		f.write('})\n');
		
		if mapLabel.marker:
			f.write('var marker = new google.maps.Marker;\n')
			f.write('\tmarker.bindTo("map", mapLabel);\n')
			f.write('\tmarker.bindTo("position", mapLabel);\n')
			f.write('\tmarker.setDraggable(true);\n')


	def drawCircle(self, f, circ):

		f.write('var coords = [\n')
		for (lat, lon) in self.getcycle(circ):
			f.write('new google.maps.LatLng(%f, %f),\n' % (lat, lon))
		f.write('];\n\n')

		f.write('var polygon = new google.maps.Polygon({\n')
		f.write('clickable: %s,\n' % (circ.clickable))
		f.write('geodesic: %s,\n' % (circ.geodesic))
		f.write('fillColor: "%s",\n' % (circ.fillColor))
		f.write('fillOpacity: %f,\n' % (circ.fillOpacity))
		f.write('paths: coords,\n')
		f.write('strokeColor: "%s",\n' % (circ.strokeColor))
		f.write('strokeOpacity: %f,\n' % (circ.strokeOpacity))
		f.write('strokeWeight: %d\n' % (circ.strokeWeight))
		f.write('});\n')
		f.write('\n')
		f.write('polygon.setMap(map);\n')
		f.write('\n\n')


	def addCircle(self, circle):
		self.circles.append(circle)

	def addText(self, mapLabel):
		self.texts.append(mapLabel)

	def getcycle(self, circle):
		cycle = []

		d = (circle.radius / 1000.0) / 6378.8;
		lat = (math.pi / 180.0) * circle.lat
		lng = (math.pi / 180.0) * circle.lon

		dangle = int(360 / MapBuilder.RESOLUTION)

		r = [x * dangle for x in range(MapBuilder.RESOLUTION)]
		for a in r:
			tc = (math.pi / 180.0) * a;
			y = math.asin(math.sin(lat) * math.cos(d) + math.cos(lat) * math.sin(d) * math.cos(tc))
			dlng = math.atan2(math.sin(tc) * math.sin(d) * math.cos(lat), math.cos(d) - math.sin(lat) * math.sin(y))
			x = ((lng - dlng + math.pi) % (2.0 * math.pi)) - math.pi
			cycle.append(( float(y * (180.0 / math.pi)), float(x * (180.0 / math.pi)) ))
		return cycle

