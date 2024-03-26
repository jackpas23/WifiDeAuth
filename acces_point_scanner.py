import sys
from scapy.all import *
from threading import Thread
import pandas as pd
import time
import os
networks= pd.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
networks.set_index("BSSID", inplace=True)
IFACE_NAME = "wlp4s0mon"
devices = set() 
ap_list=[]
  ##devices
def PacketHandler(pkt): 
    if pkt.haslayer(Dot11): 
        dot11_layer = pkt.getlayer(Dot11) 
          
        if dot11_layer.addr2 and (dot11_layer.addr2 not in devices): 
            devices.add(dot11_layer.addr2)
            ap_list.append(pkt.addr2)
            print("AP MAC: %s with SSID: %s "%(pkt.addr2,pkt.info)) 
            #print(len(devices), dot11_layer.addr2, dot11_layer.payload.name) 
  
  
sniff(iface=IFACE_NAME, count=1000, prn=PacketHandler)