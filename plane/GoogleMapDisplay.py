#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = "Jonathan Cheseaux"
__copyright__ = "Copyright 2014"
__credits__ = ["Jonathan Cheseaux", "Stefano Rosati", "Karol Kruzelecki"]
__license__ = "MIT"
__email__ = "cheseauxjonathan@gmail.com"

import sys
from PyQt4 import QtCore, QtGui, QtWebKit
from PyQt4.QtCore import *
from MapBuilder import *
import time

class GoogleMapDisplay(QtGui.QMainWindow):
	"""
	This class builds and displays a Google Map in a user interface
	
	"""
	
	def __init__(self, lat0=46.51860809, lon0=6.559470177, zoom=20, output_file="mymap.html"):
		""" Initialize the browser GUI and the MapBuilder
		
		Keyword arguments:
		lat0 -- map center's latitude
		lon0 -- map center's longitude
		zoom -- map zoom level
		output_file -- file path of the resulting html file
		"""
		QtGui.QMainWindow.__init__(self)
		self.resize(800, 600)
		self.centralwidget = QtGui.QWidget(self)
		self.mainLayout = QtGui.QHBoxLayout(self.centralwidget)
		self.mainLayout.setSpacing(0)
		self.output_file = output_file
		self.html = QtWebKit.QWebView()
		self.mainLayout.addWidget(self.html)
		self.setCentralWidget(self.centralwidget)
		self.mymap = MapBuilder(lat0, lon0, zoom, 'SATELLITE')

	def addPoint(self, lat, lon, 
				 radius=1, fillOpacity=1.0, 
				 fillColor='#00FF00', strokeColor='#000000'):
		"""Place a circle on the map
		
		Keyword arguments:
		lat -- circle latitude
		lon -- circle longitude
		radius -- the radius of this circle
		fillOpacity -- alpha
		fillColor -- color of the disk
		strokeColor -- color of the border
		"""			 			 
		self.mymap.addCircle(Circle(lat, lon, radius=radius,
									fillColor=fillColor, fillOpacity=fillOpacity,
									strokeColor=strokeColor))

	def addLabel(self, lat, lon, text,
				 fontFamily='sans-serif',fontSize=12,
				 fontColor='#000000', strokeWeight=4,
				 strokeColor='#ffffff', align='center',
				 marker=True):
		"""Place a labelled marker on the map.
		
		Keyword arguments:
		lat -- circle latitude
		lon -- circle longitude
		text -- the text to be displayed
		fontfamily -- the font of the text
		fontSize -- size of the font
		strokeWeight -- text's stroke width
		strokeColor -- color of the border
		align -- text alignment
		marker -- if True, place also a pin at the location,
				  else only display text on the map.
		"""			 			 
		self.mymap.addText(MapLabel(lat,lon,text,
									fontFamily,fontSize,
									fontColor,
									strokeWeight,
									strokeColor,
									align,marker))
									
	def clear(self):
		"""Erase every marker/labels from the map"""
		self.mymap.clear()

	def drawMap(self):
		"""Render the map and displays it in the GUI"""
		self.mymap.draw(self.output_file)
		self.html.load(QtCore.QUrl(self.output_file))
		self.html.show()

if __name__=='__main__':
	app = QtGui.QApplication([])
	gMapDisplay = GoogleMapDisplay(46.51856613, 6.560246944, zoom=20)
	gMapDisplay.addLabel(46.51856613, 6.560246944, "hello ça marche")
	gMapDisplay.addLabel(46.51867613, 6.560267944, "Ouep")
	gMapDisplay.drawMap()
	gMapDisplay.show()
	sys.exit(app.exec_())
