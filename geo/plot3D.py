#!/usr/bin/python
# -*- coding: utf-8 -*-

from mpl_toolkits.mplot3d import Axes3D
import matplotlib.pyplot as plt
import numpy as np

class plot3D():
	
	def plot(self,x,y,z):
		fig = plt.figure()
		ax = fig.add_subplot(111, projection='3d')
		ax.scatter(x, y, z)
		plt.show()
