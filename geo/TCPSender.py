#!/usr/bin/env python

import socket
import time

class TCPSender():

	def __init__(self, ip='192.168.100.90', port=8080):
		connected = False
		while not connected:
			try:
				ip = "127.0.0.1"
				self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				self.s.connect((ip, port))
				connected = True
			except socket.error, err:
				print err
				print "Trying to connect again in 10 seconds"
				time.sleep(10)
				connected = False
		
	def send(self, message):
		try:
			self.s.send(message + "\n")
		except socket.error, err:
			print err
			self.__init__()

	def close(self):
		self.s.close()

if __name__=='__main__':
	TCPSender().send()
	
