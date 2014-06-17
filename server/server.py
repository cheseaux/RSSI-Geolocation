import tornado.httpserver
import tornado.websocket
import tornado.ioloop
import tornado.web
import time
import threading
 
ws = None

onMessage = None

class WSHandler(tornado.websocket.WebSocketHandler):
	
	@staticmethod
	def subscribe(func):
		global onMessage
		print "subscribed"
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
	
	

