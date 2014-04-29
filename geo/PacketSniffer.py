#!/usr/bin/env python

import os
from scapy.all import *
from threading import Thread
import time
import sys


class Log():
    def __init__(self, path):
        self.path = path
        self.log = open(path, "a")

    def register_gps_coord(self, coord):
        self.log.write("%d\t%f\t%f\t%f" %
                       (int(time.time()), coord[0], coord[1], coord[2]))

    def write(self, client_addr, coord, signal_strength):
        self.log.write("%r\t%r\t%r\t%r\t%d" % \
                       (client_addr, coord[0], coord[1], coord[2], signal_strength))
        self.log.write(os.linesep)
        self.log.flush()


class Sniffer():
    def __init__(self):

        #Detected wireless clients and their signal's power
        self.clients_signal_power = {}

        #Virtual plane
        #self.plane = FakePlane()

        #Coordinates
        self.coord = (0, 0, 0)

        #Logging system
        self.logfile = ""

        #My iPhone mac address
        self.TARGET_MAC = "68:a8:6d:6e:a9:d8"

        #Thread responsible for reading GPS coordinates
        self.t = Thread(target=self.readSTDIN, args=())
        self.t.start()

    #Read STDIN until EOF char received
    def readSTDIN(self):
        try:
            buff = ''
            while True:
                buff += sys.stdin.read(1)
                if buff.endswith('\n'):
                    self.coord = tuple(buff[:-1].split(','))
        except KeyboardInterrupt:
            sys.stdout.flush()
            pass


    def main(self):
        #Sudo privileges needed
        #if os.geteuid() != 0:
        #exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

        iface = sys.argv[1]
        self.logfile = sys.argv[2]
        self.log = Log(self.logfile)
        #self.enableMonitorMode(iface)
        sniff(iface=iface, prn=self.trackClients, store=0)

    #To put card in monitor mode :
    @staticmethod
    def enableMonitorMode(iface):
        os.system("ifconfig " + iface + " down")
        os.system("iwconfig " + iface + " mode monitor")
        os.system("ifconfig " + iface + " up")

    #Try to deauthenticate the client
    @staticmethod
    def deauth(p):
        sendp(RadioTap() / Dot11(type=0, subtype=12, addr1=p.addr2, addr2=p.addr3, addr3=p.addr3) / Dot11Deauth())

    def bufferPower(self, user, powerVal):
        self.log.write(user, self.coord, powerVal)

    def trackClients(self, p):
        #We're only concerned by probe request packets
        #Also, sometime, addr2 is NoneType (don't know why actually)
        #p.type = 0 -> management frame

        #if not p.haslayer(Dot11) or p.addr2 is None :
        #	return

        #if p.addr2 != self.TARGET_MAC:
        #return

        #Ensure that this is a client
        #if p.type == 0 and p.subtype in (0,2,4):

        #Signal strength
        sig_str = 100 - (256 - ord(p.notdecoded[-4:-3]))
        #print p.addr2 + " detected! Signal power : " + str(sig_str)
        self.bufferPower(p.addr2, sig_str)


if __name__ == "__main__":
    Sniffer().main();
