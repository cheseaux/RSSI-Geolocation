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
import datetime
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
		self.last_keepalive = datetime.datetime.now()
		self.check_client_connection()
	
	def exit(self):
		self.interrupt = True
		
	def check_client_connection(self):
		#Check if client is still up (if he has sent a keepalive msg
		#in the last 5 seconds)
		diff = (datetime.datetime.now() - self.last_keepalive).seconds
		if diff > 5:
			print "Assuming that the client is disconnected... %d" % diff
			wsSend("disconnected")
		else:
			threading.Timer(1, self.check_client_connection).start()

	def run( self ):
		strBuffer = ""
		while True:
			try:
				strLine = (strBuffer + self.readline()).split('\n')
				strBuffer = ""
				for line in strLine:
					print "line : ",
					print line
					if line.startswith("[plane]"):
						line = line[7:]
						(planeID,lat,lon, angle) = line.split('\t');
						lat = float(lat)
						lon = float(lon)
						self.onPositionUpdated(planeID,lat,lon, angle)
					elif line.startswith("[user]"):
						line = line[6:]
						(user,lat,lon) = line.split('\t');
						lat = float(lat)
						lon = float(lon)
						
						if user in self.userPosition:
							(oldLat, oldLon) = self.userPosition[user]
							#We only update if this is a new guessed position
							if oldLat == lat and oldLon == lon:
								continue
					
						self.userPosition[user] = (lat, lon)
						self.onLocalized(user,lat,lon)
						print "User %s should be located at %f, %f" % (user,float(lat),float(lon))
					elif line.startswith("KEEPALIVE"):
						self.last_keepalive = datetime.datetime.now()	
					else:
						continue
			
			except ValueError, err:
				print "ERR ClientThread",
				print line
				print "End of line----"
				strBuffer += line
				continue
			

		self.client.close()
		return

	def readline( self ):
		result = self.client.recv( 256 )
		#print "RCVD " + result
		if( None != result ):
			result = result
		return result

class Server():

	def __init__( self ):
		self.sock = None
		self.thread_list = []
		t = threading.Thread(target=launch_server)
		t.start()
		
		
	def addGuess(self,user,lat,lon):
		wsSend("[u]%r\t%f\t%f" % (user,lat,lon))
		
	def addPlanePosition(self,planeID,lat,lon, angle):
		wsSend("[p]%r\t%f\t%f\t%d" % (planeID,lat,lon, int(angle)))
		
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
		return self.client.recv( 256 )

if "__main__" == __name__:
	server = Server()
	server.run()

