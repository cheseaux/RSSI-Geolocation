#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import time
import sys
from threading import Thread
from math import cos, pi, sin


class FakePlane():
    def __init__(self, send_position=False):
        self.angle = 0.0
        self.r = 0.002
        self.center = (46.518394, 6.568469)

        if send_position:
            Thread(target=self.nextCoordinateCircle, args=()).start()

    def get_coordinate(self):
        return self.x, self.y

    def nextCoordinateCircle(self):
        while(True):
            self.x = self.center[0] + self.r * cos(self.angle)
            self.y = self.center[1] + self.r * sin(self.angle)
            self.angle += 0.1
            if self.angle >= 2 * pi:
                self.angle = 0.0
            print "%f, %f, %f" % (self.x, self.y, 42)
            sys.stdout.flush()
            time.sleep(1)

    def getCoord(self):
        return (self.x, self.y)


if __name__ == "__main__":
    plane = FakePlane(True)


