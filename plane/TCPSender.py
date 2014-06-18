#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = "Jonathan Cheseaux"
__copyright__ = "Copyright 2014"
__credits__ = ["Jonathan Cheseaux", "Stefano Rosati", "Karol Kruzelecki"]
__license__ = "MIT"
__email__ = "cheseauxjonathan@gmail.com"


import socket
import time
from threading import Thread
import threading

class TCPSender(Thread):
	"""This class implements a TCP connection between
	the plane and the base station.
	"""
	
	def __init__(self, ip='192.168.100.92', port=8080):
		Thread.__init__(self)
		self.message_buffer = []
		self.ip = ip
		self.port = port
		self.connected = False
		self.reconnecting = False
		self.s = None
		
	def run(self):
		self.connected = False
		self.connect()
		
	def connect(self):
		"""Connects to the server (base station) """
		
		print "Connecting to server..."	
		while not self.connected:
			try:
				self.reconnecting = True
				self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				self.s.connect((self.ip, self.port))
				self.connected = True
				self.reconnecting = False
				print "Connection established"
				self.send_keepalive()
				while not len(self.message_buffer) == 0:
					#the message will be buffered if a disconnection happens again
					#so we can safely remove the message from the buffer from now
					msg = self.message_buffer.pop()
					print "Sending buffered message (remaining : %d" % len(self.message_buffer)
					self.send(msg)
					
			except socket.error, err:
				print "Trying to connect again in 5 seconds"
				time.sleep(5)
				self.s.close()
				self.connected = False
				self.reconnecting = True
		
	def send_keepalive(self):
		"""KEEPALIVE message are required in order to detect quickly
		a disconnection between the plane and the base station.
		False positive can arise from this system, and the tolerance
		(time between successive KEEPALIVE message) need to be
		adjusted on both the server (server/ThreadedServer.py) and
		the following timer (setted to 3 by default)
		"""
		self.send("KEEPALIVE")
		threading.Timer(3, self.send_keepalive).start()	
		
	def receive(self):
		""" Reads the socket's inputstream for received message"""
		if not self.connected:
			return None
			
		data = self.s.recv(1024) 
		if data: 
			instructions = data.split("\n")
			if data.lower().startswith("[routing]"):
				(header, lat,lon,radius) = data.split("\t")
				return (header, lat, lon, radius)
		return None
		
	def send(self, message, retry=False):
		"""
		Send a message to the socket's outputstream
		If the connection drop, the plane can buffer
		the messages and resend them once the connection
		is up again.
		"""
		try:
			if not self.connected and retry:
				self.message_buffer.append(message)
				print "Server not connected yet. Buffering %s [total : %d]" % (message, len(self.message_buffer))
			else:
				self.s.send(message + "\n")
		except socket.error, err:
			if retry:
				self.message_buffer.append(message)
			print "Server not connected. Buffering message [total : %d]" % len(self.message_buffer)
			if not self.reconnecting:
				print "Process reconnection..."
				self.connected = False
				Thread(target=self.connect, args = ()).start()


if __name__=='__main__':
	TCPSender().send()
	
