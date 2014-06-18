#!/usr/bin/env python
# -*- coding: utf8 -*-
# Copied and adapted from http://www.eurion.net/python-snippets/snippet/Threaded%20Server.html
# GPL license

import sys
import os
import socket
from threading import Thread
import time
import datetime
from server import *

application = tornado.web.Application([
    (r'/ws', WSHandler),
])

PORT = 8888

MAX_PLANE_NUMBER = 20

def launch_server():
	http_server = tornado.httpserver.HTTPServer(application)
	http_server.listen(PORT)
	WSHandler.subscribe(ClientThread.notifyRouting)
	tornado.ioloop.IOLoop.instance().start()

client_socket = None	

class ClientThread( Thread ):
	"""Thread responsible for communicating with a plane """
	
	@staticmethod
	def notifyRouting(message):
		"""Relay a routing message from the websocket to the plane"""
		global client_socket
		#print "PASSED FROM WSOCKET : " + message
		client_socket.send(message)
		
	def __init__( self, server_sock, client_sock, onLocalized, onPositionUpdated, onBeacon):		
		Thread.__init__( self )
		self.client = client_sock
		global client_socket
		client_socket = client_sock
		self.userPosition = {}
		self.onLocalized = onLocalized
		self.onPositionUpdated = onPositionUpdated
		self.onBeacon = onBeacon
		self.interrupt = False
		self.last_keepalive = datetime.datetime.now()
		self.check_client_connection()
	
	def exit(self):
		self.interrupt = True
		
	def check_client_connection(self):
		"""If no KEEPALIVE message are received from the last 7 seconds
		we suppose that the connection between the plane and the server
		is lost"""
		
		#Check if client is still up (if he has sent a keepalive msg
		#in the last 6 seconds)
		diff = (datetime.datetime.now() - self.last_keepalive).seconds
		if diff > 6:
			print "Assuming that the client is disconnected... %d" % diff
			wsSend("disconnected")
		else:
			threading.Timer(1, self.check_client_connection).start()

	def run( self ):
		"""This method reads the message sent by the plane
		and triggers the corresponding action"""
		
		strBuffer = ""
		while True:
			try:
				strLine = (strBuffer + self.readline()).split('\n')
				strBuffer = ""
				for line in strLine:
					line = line.lower()
					#Plane position received
					if line.startswith("[plane]"):
						line = line[7:]
						(planeID,lat,lon, angle) = line.split('\t');
						lat = float(lat)
						lon = float(lon)
						self.onPositionUpdated(planeID,lat,lon, angle)
					#Beacon received (Probe Request)
					elif line.startswith("[beacon]"):
						line = line[8:]
						(user,lat,lon, pwr) = line.split('\t');
						lat = float(lat)
						lon = float(lon)
						pwr = float(pwr)
						#print "Threaded server received beacon !"
						self.onBeacon(user,lat,lon,pwr)
					#Plane has localized a user
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
						print "User %s localized at %.8f, %.8f" % (user,lat,lon)
					elif line.startswith("KEEPALIVE"):
						self.last_keepalive = datetime.datetime.now()
					elif line.startswith("[routing]"):
						(neLat, neLng, swLat, swLng) = line.split("\t")
					else:
						continue
			
			except ValueError, err:
				strBuffer += line
				continue

		self.client.close()
		return

	def readline( self ):
		result = self.client.recv( 256 )
		if( None != result ):
			result = result
		return result

class Server():
	""" This is the server part of the TCP connection.
	It is responsible for listening to new incoming connections
	and communicate with the websocket to update the live GUI
	"""
	
	def __init__( self ):
		os.system("fuser -k -n tcp " + str(PORT))
		self.sock = None
		self.thread_list = []
		t = threading.Thread(target=launch_server)
		t.start()
		
	def addGuess(self,user,lat,lon):
		wsSend("[u]%r\t%.8f\t%.8f" % (user,lat,lon))
		
	def addBeacon(self,user,lat,lon,pwr):
		print "Beacon received! : %s" % user
		wsSend("[b]%r\t%.8f\t%.8f\t%f" % (user,lat,lon, pwr))
		
	def addPlanePosition(self,planeID,lat,lon, angle):
		print "Position received : %.8f %.8f %.8f" % (lat,lon,int(angle))
		wsSend("[p]%r\t%.8f\t%.8f\t%d" % (planeID,lat,lon, int(angle)))
		
		
	def run( self ):
		
		connected = False
		while not connected:
			try:
				self.sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
				#self.sock.bind( ( '127.0.0.1', 8080 ) )
				self.sock.bind( ( '192.168.100.92', 8080 ) )
				self.sock.listen( MAX_PLANE_NUMBER )
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
				new_thread = ClientThread(self.sock, client, self.addGuess, self.addPlanePosition, self.addBeacon)
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

