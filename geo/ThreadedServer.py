#!/usr/bin/env python
# -*- coding: utf8 -*-
# Copied and adapted from http://www.eurion.net/python-snippets/snippet/Threaded%20Server.html
# GPL license



#TODO :
# TCP sender reconnect in another thread
# Select MAC from base station and sends routing information (from map or script, the easiest the best)
#



import sys
import socket
from threading import Thread
import time
from MapBuilder import *
from server import *


application = tornado.web.Application([
    (r'/ws', WSHandler),
])

def launch_server():
	http_server = tornado.httpserver.HTTPServer(application)
	http_server.listen(8888)
	tornado.ioloop.IOLoop.instance().start()

class ClientThread( Thread ):

	def __init__( self, client_sock, onLocalized, onPositionUpdated):
		Thread.__init__( self )
		self.client = client_sock
		self.userPosition = {}
		self.onLocalized = onLocalized
		self.onPositionUpdated = onPositionUpdated
		self.interrupt = False
	
	def exit(self):
		self.interrupt = True

	def run( self ):

		while not self.interrupt:
			try:
				strLine = self.readline()
				if strLine.startswith("[plane]"):
					strLine = strLine[7:]
					(planeID,lat,lon, angle) = strLine.split('\t');
					lat = float(lat)
					lon = float(lon)
					self.onPositionUpdated(planeID,lat,lon, angle)
					print "Updated plane position"
				elif strLine.startswith("[user]"):
					strLine = strLine[6:]
					(user,lat,lon) = strLine.split('\t');
					lat = float(lat)
					lon = float(lon)
					
					if user in self.userPosition:
						(oldLat, oldLon) = self.userPosition[user]
						#We only update if this is a new guessed position
						if oldLat == lat and oldLon == lon:
							continue
				
					self.userPosition[user] = (lat, lon)
					self.onLocalized(user,lat,lon)
					print "User %s should be at %f, %f" % (user,float(lat),float(lon))
					
				else:
					continue
			
			except ValueError, err:
				print err
				continue
			

		self.client.close()
		return

	def readline( self ):
		result = self.client.recv( 256 )
		if( None != result ):
			result = result.strip().lower()
		return result

class Server():

	def __init__( self ):
		self.sock = None
		self.thread_list = []
		self.mapBuild = MapBuilder(46.518394, 6.568469, zoom=16, mapType='SATELLITE')
		self.userMarker = {}
		t = threading.Thread(target=launch_server)
		t.start()
		
		
	def addGuess(self,user,lat,lon):
		wsSend("[u]%r\t%f\t%f" % (user,lat,lon))
		#self.userMarker[user] = MapLabel(lat=lat,lon=lon,text=user)
		#self.drawMap()
		
	def addPlanePosition(self,planeID,lat,lon, angle):
		wsSend("[p]%r\t%f\t%f\t%d" % (planeID,lat,lon, int(angle)))
		#self.userMarker[user] = MapLabel(lat=lat,lon=lon,text=user)
		#self.drawMap()
		
	def drawMap(self):
		self.mapBuild.clear()
		for user in self.userMarker:
			self.mapBuild.addText(self.userMarker[user])
		
		self.mapBuild.draw('mymap.html')
		
	def run( self ):
		
		connected = False
		while not connected:
			try:
				self.sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
				self.sock.bind( ( '127.0.0.1', 8080 ) )
				self.sock.listen( 10 )
				print "Listening for plane communications"
				connected = True
			except socket.error, err:
				print err
				time.sleep(5)
				connected = False

		interrupted = False
		while not interrupted:
			try:
				client = self.sock.accept()[0]
				new_thread = ClientThread( client, self.addGuess, self.addPlanePosition)
				print 'Incoming plane connection'
				self.thread_list.append( new_thread )
				new_thread.start()

			except KeyboardInterrupt:
				print 'Ctrl+C pressed... Shutting Down'
				for thread in self.thread_list:
					thread.exit()
				interrupted = True
			except Exception, err:
				print 'Exception caught: %s\nClosing...' % err
				print 'Restarting server in 10 seconds...'
				self.run()
		

		self.sock.close()
	
	def readline( self ):
		result = self.client.recv( 256 )
		if( None != result ):
			result = result.strip().lower()
		return result

if "__main__" == __name__:
	server = Server()
	server.run()

