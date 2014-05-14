from websocket import create_connection
import time

ws = create_connection("ws://localhost:9998")
time.sleep(10)
print "Sending 'Hello, World'..."
ws.send("Hello, World")
print "Sent"
print "Reeiving..."
result =  ws.recv()
print "Received '%s'" % result
ws.close()
