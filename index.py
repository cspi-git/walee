# Dependencies
from scapy.all import *
import requests
import socket
import os

# Variables
hostname = socket.gethostname()
localIP = socket.gethostbyname(hostname)

whitelistedIPs = [] # Whitelist some IPs
tempBlocked = []
excludedIPs = []

# Functions
def packetChecker(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip = packet[IP].src
        if ip not in whitelistedIPs and ip not in excludedIPs and ip != localIP:
            # print(f"SRC: {ip} DST: {packet[IP].dst}")
            response = requests.get(f"https://v2.api.iphub.info/guest/ip/{ip}?c=Fae9gi8a")
            response = response.json()
            if response["block"] == 1:
                if ip not in tempBlocked:
                    tempBlocked.append(ip)
                    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
                    print(f"IP: {ip} is suspicious and has been blocked.")
            else:
                excludedIPs.append(ip)
                print(f"IP: {ip} has been excluded.")

# Main
sniff(filter="tcp", prn=packetChecker)