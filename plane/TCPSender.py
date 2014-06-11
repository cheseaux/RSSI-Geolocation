#!/usr/bin/env python

import socket
import time
from threading import Thread
import threading

class TCPSender(Thread):

	def __init__(self, ip='192.168.100.90', port=8080):
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
		print "Connecting to server..."	
		while not self.connected:
			try:
				self.reconnecting = True
				self.ip = "127.0.0.1"
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
		self.send("KEEPALIVE")
		print "Sending KEEPALIVE"
		threading.Timer(3, self.send_keepalive).start()	
		
	def receive(self):
		if not self.connected:
			return None
			
		data = self.s.recv(1024) 
		if data: 
			instructions = data.split("\n")
			if data.lower().startswith("[routing]"):
				(header, neLat,neLng,swLat,swLng) = data.split("\t")
				return (header, neLat,neLng,swLat,swLng)
		return None
		
	def send(self, message):
		try:
			if not self.connected:
				self.message_buffer.append(message)
				print "Server not connected yet. Buffering message [total : %d]" % len(self.message_buffer)
			else:
				self.s.send(message + "\n")
		except socket.error, err:
			self.message_buffer.append(message)
			print "Server not connected. Buffering message [total : %d]" % len(self.message_buffer)
			if not self.reconnecting:
				print "Process reconnection..."
				self.connected = False
				Thread(target=self.connect, args = ()).start()
				


if __name__=='__main__':
	TCPSender().send()
	
