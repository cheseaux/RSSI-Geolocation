#!/usr/bin/python
# -*- coding: utf-8 -*-

import pygmaps 
import sys
from PyQt4 import QtCore, QtGui, QtWebKit
from PyQt4.QtCore import *
from fakePlane import FakePlane
import time

class Browser(QtGui.QMainWindow):

	def __init__(self):
		"""
			Initialize the browser GUI and connect the events
		"""
		QtGui.QMainWindow.__init__(self)
		self.resize(800,600)
		self.centralwidget = QtGui.QWidget(self)
	
		self.mainLayout = QtGui.QHBoxLayout(self.centralwidget)
		self.mainLayout.setSpacing(0)
	
		self.html = QtWebKit.QWebView()
		self.mainLayout.addWidget(self.html)
		self.setCentralWidget(self.centralwidget)
		
		self.plane = FakePlane()
		self.trackPlane()
		self.timer = QtCore.QTimer(self)
		self.timer.timeout.connect(self.trackPlane)
		self.timer.start(1000)
		
		
	def trackPlane(self):
		coord = self.plane.nextCoordinateCircle()
		mymap = pygmaps.maps(46.518394,6.568469, 16)
		mymap.addradpoint(coord[0], coord[1], 9, "#0000FF")
		url = 'mymap.draw.html'
		mymap.draw(url)
		self.html.load(QtCore.QUrl(url))
		self.html.show()	
		print "toto"
       
if __name__ == "__main__":
	
	app = QtGui.QApplication(sys.argv)
	main = Browser()
	main.show()
	sys.exit(app.exec_())

