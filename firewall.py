#!/bin/python3

#this firewall runs for proxy,packet filtering,statefulfiltering and net gen


import logging   #used to create logs of all firewall activities
from scapy.all import *    #import full scapy library for packet manipulation
import http.server    #http.server and socketserver help to create a simple http server to implement proxy firewall functionality
import socketserver
import random   #used for generating random numbers 
import time
import select
import socket
#time,select and socket sre used for timeouts,managing connects and networks
# Set up logging
logging.basicConfig(filename="firewall.log", level=logging.INFO)

# Firewall rules (allow HTTP and ICMP, block others by default)
RULES = [
    {"src_ip": "any", "dst_ip": "any", "protocol": "TCP", "dst_port": 80},  # Allow HTTP
    {"src_ip": "any", "dst_ip": "any", "protocol": "ICMP", "dst_port": "any"},  # Allow ICMP for pings is allowed
]
#listiing out the rules  <tcp on port 80 is allowed>
# State Table for Stateful Filtering
state_table = {}  #this dictionary tracks state of connection.

# Function to simulate DPI for next-gen firewall (mock)
def deep_packet_inspection(pkt):  #the function  checks the payload of each packet checking fr malicious  contents
    """Perform basic DPI to inspect packet content."""
    if pkt.haslayer(Raw):  #checks if packets has raw layer containing gthe actual data<payloads>
        payload = pkt[Raw].load
        if b"malicious" in payload:  # Example of a simple DPI rule<looks for the word malicious in payloads>
            logging.warning(f"Malicious content detected in packet: {pkt.summary()}")
            return False
    return True  #if content is malicious , the function logs the event and false drop the packet

def is_established_connection(ip_src, ip_dst, src_port, dst_port):
#checks whether the connection between two IP addresses and ports is already established  by searcing for connection in the state_table
#if the ip_src, ip_dst, src_port, dst_port exist in the staate-table connection is already establsihed
    """Check if the connection is in the state table (i.e., established)."""
    return state_table.get((ip_src, ip_dst, src_port, dst_port)) is not None

# Packet Filtering (Basic)
def packet_filter(pkt): #checks whether packet matches any of the rues defined earlier
    """Packet filter with basic rule-based filtering."""
    for rule in RULES:
        if pkt.haslayer(IP):
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            proto = pkt.proto
            if proto == 6:  # TCP
                if pkt.haslayer(TCP):
                    dst_port = pkt[TCP].dport
                    if rule['protocol'] == 'TCP' and rule['dst_port'] == dst_port and (rule['src_ip'] == "any" or rule['src_ip'] == ip_src) and (rule['dst_ip'] == "any" or rule['dst_ip'] == ip_dst):
                        logging.info(f"Packet allowed: {pkt.summary()}")
                        return
            elif proto == 1:  # ICMP
                if rule['protocol'] == 'ICMP':
                    logging.info(f"Packet allowed: {pkt.summary()}")
                    return

    logging.warning(f"Packet dropped: {pkt.summary()}")
    return None

# Stateful Filtering
def packet_filter_stateful(pkt):
    """Packet filter with stateful tracking."""
    if pkt.haslayer(IP):
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        proto = pkt.proto
        if proto == 6:  # TCP
            if pkt.haslayer(TCP):
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                if is_established_connection(ip_src, ip_dst, src_port, dst_port):
                    logging.info(f"Established connection packet allowed: {pkt.summary()}")
                    return
                else:
                    # Track new connection
                    state_table[(ip_src, ip_dst, src_port, dst_port)] = 'ESTABLISHED'
                    logging.info(f"New connection started: {pkt.summary()}")
                    return
        elif proto == 1:  # ICMP
            logging.info(f"ICMP allowed: {pkt.summary()}")
            return

    logging.warning(f"Packet dropped: {pkt.summary()}")
    return None

# Proxy Firewall for HTTP requests
class ProxyRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests."""
        logging.info(f"GET request: {self.path}")
        if "bad_request" in self.path:
            self.send_error(403, "Forbidden")
        else:
            super().do_GET()

    def do_POST(self):
        """Handle POST requests."""
        logging.info(f"POST request: {self.path}")
        if "bad_request" in self.path:
            self.send_error(403, "Forbidden")
        else:
            super().do_POST()

# Next-Gen Firewall: A mock function to integrate DPI
def next_gen_firewall(pkt):
    """Simulate Next-Gen Firewall features."""
    if not deep_packet_inspection(pkt):
        return None
    return packet_filter_stateful(pkt)

# Function to start the packet filter
def start_firewall():
    """Start packet filter and handle multiple connections."""
    print("Firewall started... Press CTRL+C to stop.")
    sniff(prn=next_gen_firewall, store=0)

# Function to start the proxy firewall
def run_proxy():
    """Start a simple HTTP proxy server."""
    PORT = 8080
    logging.basicConfig(filename="proxy_firewall.log", level=logging.INFO)
    with socketserver.TCPServer(("", PORT), ProxyRequestHandler) as httpd:
        print(f"Proxy firewall running on port {PORT}")
        httpd.serve_forever()

# Simple Stateful Filter (simulate firewall with select)
def run_stateful_proxy():
    """Stateful proxy filter using select for handling multiple connections."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 8080))
    s.listen(5)
    print("Stateful Proxy listening...")
    
    while True:
        rlist, _, _ = select.select([s], [], [])
        for sock in rlist:
            client, addr = sock.accept()
            print(f"Connection from {addr}")
            client.close()

# Main entry to start firewalls
if __name__ == "__main__":
    start_firewall()  # Start packet filtering and stateful firewall
    # Uncomment to run proxy:
    # run_proxy()
    # Uncomment to run stateful proxy:
    # run_stateful_proxy()

