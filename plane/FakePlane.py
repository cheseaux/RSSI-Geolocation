#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = "Jonathan Cheseaux"
__copyright__ = "Copyright 2014"
__credits__ = ["Jonathan Cheseaux", "Stefano Rosati", "Karol Kruzelecki"]
__license__ = "MIT"
__email__ = "cheseauxjonathan@gmail.com"

import os
import time
import sys
from threading import Thread
from math import cos, pi, sin

class FakePlane():
	"""
	This class simulate a plane for debuggin purpose.
	It simply follows a circle whose radius increase over time
	(Spiral path)
	"""
	
    def __init__(self):
		"""Build a new simulated plane"""
        self.angle = 0.0
        self.r = 0.002
        self.center = (46.51839432, 6.56846932)
        Thread(target=self.nextCoordinateCircle, args=()).start()

    def nextCoordinateCircle(self):
		"""Compute the next coordinates of the path followed"""
        while(True):
            self.x = self.center[0] + self.r * cos(self.angle)
            self.y = self.center[1] + self.r * sin(self.angle)
            self.angle += 0.1
            self.r += 0.0001
            if self.angle >= 2 * pi:
                self.angle = 0.0
            print "%.8f, %.8f, %.8f, %.8f, %s, %f" % (self.x, self.y, 42, 350, "foo", 189)
            sys.stdout.flush()
            time.sleep(1)

if __name__ == "__main__":
    plane = FakePlane()


