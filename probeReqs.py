import sys
from scapy.all import *
import pandas as pd
import time
import os
import threading

from datetime import datetime
from scapy.all import sniff, Dot11
#import numpy
import logging
import time
#Devices which are known to be constantly probing
IGNORE_LIST = set(['00:00:00:00:00:00', '01:01:01:01:01:01'])
SEEN_DEVICES = set() #Devices which have had their probes recieved
d = {'00:00:00:00:00:00':'Example MAC Address'} #Dictionary of all named devices
IFACE_NAME='wlp4s0mon'
def handle_packet(pkt):
	if pkt.haslayer(Dot11Beacon):
		return
	if pkt.type == 0 and pkt.subtype == 4: #subtype used to be 8 (APs) but is now 4 (Probe Requests)
		#logging.debug('Probe Recorded with MAC ' + curmac)
		curmac = pkt.addr2
		curmac = curmac.upper() #Assign variable to packet mac and make it uppercase
		SEEN_DEVICES.add(curmac) #Add to set of known devices (sets ignore duplicates so it is not a problem)
		if curmac not in IGNORE_LIST: #If not registered as ignored
			if curmac in d:
				logging.info('\033[95m' + 'Probe Recorded from ' + '\033[93m' + d[curmac] + '\033[95m' + ' with MAC ' + curmac + '\033[0m')
				print('\033[95m' + 'Probe MAC Address: ' + pkt.addr2 + ' from device ' + '\033[93m' + d[curmac] + '\033[0m')
                                        #'with SSID: {pkt.info}'.format(pkt=pkt)) #Print to command line with purple color
			else:
				logging.info('\033[92m' + 'Probe Recorded from MAC ' + pkt.addr2 + '\033[0m') #Log to file wifiscanner.log with green color
				print('\033[95m' + 'Device MAC: {pkt.addr2} '
					'with SSID: {pkt.info}'.format(pkt=pkt) + '\033[0m') #Print to command line with green color
			#print SEEN_DEVICES #Just for debug, prints all known devices
			#dump()

sniff(iface=IFACE_NAME, prn=handle_packet)