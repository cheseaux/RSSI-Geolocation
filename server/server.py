#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = "Jonathan Cheseaux"
__copyright__ = "Copyright 2014"
__credits__ = ["Jonathan Cheseaux", "Stefano Rosati", "Karol Kruzelecki"]
__license__ = "MIT"
__email__ = "cheseauxjonathan@gmail.com"

import tornado.httpserver
import tornado.websocket
import tornado.ioloop
import tornado.web
import time
import threading
 
ws = None

onMessage = None #Method called when a message is received from the websocket

class WSHandler(tornado.websocket.WebSocketHandler):
	"""This class uses the Tornado library which allows to deal
	with WebSockets. This permit to communicate with a JavaScript/JQuery
	script in a html page.
	It is used by ThreadedServer.py to interact with the live interface
	"""
	
	@staticmethod
	def subscribe(func):
		""" Defines the method called when a message
		is received from the websocket"""
		global onMessage
		onMessage = func
	
	def open(self):
		global ws
		print "Ws before : ",
		print ws
		ws = self
		print 'Web UI connected ',
		print ws
			  
	def on_message(self, message):
		global onMessage
		print 'message received %s' % message
		onMessage(message)

	def on_close(self):
		global ws
		print 'connection closed'
		ws = None
 
application = tornado.web.Application([
    (r'/ws', WSHandler),
])

def wsSend(message):
	"""Sends a message to the websocket end (live interface)"""
	if None != ws and ws.ws_connection.stream.socket:
		ws.write_message(message)
	else:
		print "Web socket disconnected !"

def launch_server():
	http_server = tornado.httpserver.HTTPServer(application)
	http_server.listen(8888)
	tornado.ioloop.IOLoop.instance().start()
 
if __name__ == "__main__":
	t = threading.Thread(target=launch_server)
	t.start()
	
	

