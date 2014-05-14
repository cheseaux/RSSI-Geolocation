import tornado.httpserver
import tornado.websocket
import tornado.ioloop
import tornado.web
import time
import threading
 
wss =[]

class WSHandler(tornado.websocket.WebSocketHandler):
	def open(self):
		if self not in wss:
			wss.append(self)
		print 'new connection'
		time.sleep(3)
		self.write_message("Hello World")
			  
	def on_message(self, message):
		print 'message received %s' % message

	def on_close(self):
	  print 'connection closed'
 
application = tornado.web.Application([
    (r'/ws', WSHandler),
])

def wsSend(message):
	for ws in wss:
		if not ws or not ws.ws_connection.stream.socket:
			print "Web socket does not exist anymore!!!"
			wss.remove(ws)
		else:
			print "message written to websocket"
			ws.write_message(message)

def launch_server():
	http_server = tornado.httpserver.HTTPServer(application)
	http_server.listen(8888)
	tornado.ioloop.IOLoop.instance().start()
 
if __name__ == "__main__":
	t = threading.Thread(target=launch_server)
	t.start()
	print "blablalbal"
	
	

