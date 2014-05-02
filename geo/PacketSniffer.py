#!/usr/bin/env python

import os
from scapy.all import *
from threading import Thread
import time
import sys


class Log():
    def __init__(self, path):
        self.logGPS = open(path + "_gps.txt", "a")
        self.logBeacon = open(path + "_beacon.txt", "a")


    def register_gps_coord(self, coord):
        self.logGPS.write("%d\t%f\t%f\t%f" %
                       (int(round(time.time() * 1000)), float(coord[0]), float(coord[1]), float(coord[2])))
        self.logGPS.write(os.linesep)
        self.logGPS.flush()
        print "Registred GPS position\n"

    def write(self, client_addr, signal_strength):
        self.logBeacon.write("%d\t%r\t%d" % \
                       (int(round(time.time() * 1000)), client_addr, signal_strength))
        self.logBeacon.write(os.linesep)
        self.logBeacon.flush()
        #print "Registred Beacon signal\n"

class Sniffer():
    def __init__(self, path):

        #Detected wireless clients and their signal's power
        self.clients_signal_power = {}

        #Virtual plane
        #self.plane = FakePlane()

        #Coordinates
        self.coord = (0, 0, 0)

        #Logging system
        self.log = Log(path)

        #My iPhone mac address
        self.TARGET_MAC = "68:a8:6d:6e:a9:d8"

        #Thread responsible for reading GPS coordinates
        self.t = Thread(target=self.readSTDIN, args=()).start()


    #Read STDIN until EOF char received
    def readSTDIN(self):
        try:
            buff = ''
            while True:
                line = sys.stdin.readline()
                if line == '':
                    break
                self.log.register_gps_coord(line.split(','))
                #self.coord = tuple(buff[:-1].split(','))
        except KeyboardInterrupt:
            sys.stdout.flush()
            pass


    def main(self):
        #Sudo privileges needed
        #if os.geteuid() != 0:
        #exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

        iface = sys.argv[1]
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
        self.log.write(user, powerVal)

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
    a = Sniffer(sys.argv[2])
    a.main();
