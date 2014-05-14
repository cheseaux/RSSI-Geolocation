import tornado.httpserver
import tornado.websocket
import tornado.ioloop
import tornado.web
 
 
class WSHandler(tornado.websocket.WebSocketHandler):
	
	def __init__(self):
		http_server = tornado.httpserver.HTTPServer(application)
		http_server.listen(8888)
		tornado.ioloop.IOLoop.instance().start()

    def open(self):
        print 'new connection'
    
    def send(self, lat,lon,user):
		self.write_message("%f,%f,%r" % (lat,lon,user))
      
    def on_message(self, message):
        print 'message received %s' % message
 
    def on_close(self):
      print 'connection closed'
 
 
application = tornado.web.Application([
    (r'/ws', WSHandler),
])
 
 
if __name__ == "__main__":
    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(8888)
    tornado.ioloop.IOLoop.instance().start()
