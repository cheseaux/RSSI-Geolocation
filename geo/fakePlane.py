#!/usr/bin/python
# -*- coding: utf-8 -*-

#Center = 46.518394,6.568469

from math import cos, pi, sin
import time
import sys
from threading import Thread

class FakePlane():

	def __init__(self):
		self.angle = 0.0
		self.r = 0.002
		self.center = (46.518394,6.568469)
		
		Thread(target=self.nextCoordinateCircle, args = ()).start()
		
	def nextCoordinateCircle(self):
		while True:
			self.x = self.center[0] + self.r * cos(self.angle)
			self.y = self.center[1] + self.r * sin(self.angle)
			self.angle += 0.1
			if self.angle >= 2*pi:
				self.angle = 0.0
			#print "%f : %f" % (self.x,self.y)
			
			time.sleep(1)
			
	def getCoord(self):
		return (self.x, self.y)
	        
if __name__ == "__main__":
	plane = FakePlane()
	

