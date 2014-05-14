#!/usr/bin/env python

import socket

class Server():
	
	def __init__(self, ip, port):
		self.TCP_IP = ip
		self.TCP_PORT = port
		self.BUFFER_SIZE = 1024
		
	def start(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.bind((self.TCP_IP, self.TCP_PORT))
		s.listen(1)
	
		conn, addr = s.accept()
		print 'Connection address:', addr
		while 1:
		    data = conn.recv(self.BUFFER_SIZE)
		    if not data: break
		    print "received data:", data
		    conn.send(data)  # echo
		conn.close()
		
