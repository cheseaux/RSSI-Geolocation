#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
from PyQt4 import QtCore, QtGui, QtWebKit
from PyQt4.QtCore import *
from MapBuilder import *
import time

class GoogleMapDisplay(QtGui.QMainWindow):
	def __init__(self, lat0=46.51860809, lon0=6.559470177, zoom=20, output_file="mymap.html"):
		"""
			Initialize the browser GUI and connect the events
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
					 			 
		self.mymap.addCircle(Circle(lat, lon, radius=radius,
									fillColor=fillColor, fillOpacity=fillOpacity,
									strokeColor=strokeColor))

	def addLabel(self, lat, lon, text,
				 fontFamily='sans-serif',fontSize=12,
				 fontColor='#000000', strokeWeight=4,
				 strokeColor='#ffffff', align='center',
				 marker=True):

		self.mymap.addText(MapLabel(lat,lon,text,
									fontFamily,fontSize,
									fontColor,
									strokeWeight,
									strokeColor,
									align,marker))
									
	def clear(self):
		self.mymap.clear()

	def drawMap(self):
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
