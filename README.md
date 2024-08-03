Imports and Setup:

Imports scapy, argparse, and HTTP layers from Scapy.
Uses argparse to handle command-line arguments for specifying the network interface.
Function Definitions:

get_interface(): Parses command-line arguments to get the network interface.
sniff(iface): Sniffs network packets on the given interface, calling process_packet for each packet.
Packet Processing:

process_packet(packet):
Checks for HTTP requests in the packet.
Extracts and prints the HTTP method, host, and path.
For POST requests, looks for sensitive data (e.g., usernames, passwords) in the raw payload and prints potential credentials if found.
Execution:

Gets the network interface from command-line arguments.
Starts sniffing on the specified interface.
Use Case:

Useful for network analysis and monitoring HTTP traffic to identify sensitive information being transmitted.
