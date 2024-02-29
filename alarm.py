

#!/usr/bin/python3

from scapy.all import *
import argparse
import re
import base64

# Initialize incident counter
incident_number = 0
# VNC Ports for both direct connections and web-based access
VNC_PORTS = list(range(5900, 5904)) + list(range(5800, 5804))

def packetcallback(packet):
    global incident_number
    try:
        # Check for NULL, FIN, XMAS, RDP, VNC and SMB scans
        if packet.haslayer(TCP):
            check_scans(packet)
        
         # Check for Nikto scan and credentials in plaintext protocols
        if packet.haslayer(Raw):
            check_credentials_and_nikto(packet)
    except Exception as e:
        print(f"General Error processing packet: {e}")

def check_scans(packet):
    global incident_number
    try:
     tcp_flags = packet[TCP].flags
     dst_port = packet[TCP].dport
     # NULL Scan: No flags set
     if tcp_flags == 0:
        incident_number += 1
        print_incidents("NULL scan", packet)
     # FIN Scan: Only the FIN flag is set
     elif tcp_flags == 'F' or tcp_flags == 0x01:
        incident_number += 1
        print_incidents("FIN scan", packet)
     # XMAS Scan: FIN, PSH, and URG flags are set
     elif tcp_flags == 'FPU' or tcp_flags == 0x29:
        incident_number += 1
        print_incidents("Xmas scan", packet)
     # RDP and SMB scans by destination port
     if dst_port == 3389:
        incident_number += 1
        print_incidents("RDP scan", packet)
     elif dst_port in [139, 445]:
        incident_number += 1
        print_incidents("SMB scan", packet)
     # VNC scan detection
     if dst_port in VNC_PORTS:
        incident_number += 1
        print_incidents("VNC scan", packet)
    except Exception as e:
     print(f"Error processing scan detection: {e}")
  


def check_credentials_and_nikto(packet):   

    global incident_number
    try:
     payload = packet[Raw].load.decode('latin-1', 'ignore')
     # Nikto scan via HTTP User-Agent
     if "nikto" in payload.lower():
        incident_number += 1
        print_incidents("Nikto scan", packet)
     # HTTP Basic Authentication credentials
     elif "authorization: basic" in payload.lower():
        creds = extract_http_creds(payload)
        if creds:
            incident_number += 1
            print_incidents("Usernames and passwords sent in-the-clear via HTTP (Basic Auth)", packet, creds)
     # FTP credentials
     elif packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):
        if "USER" in payload or "PASS" in payload:
            creds = extract_ftp_creds(packet,payload)
            if creds:
                incident_number += 1
                print_incidents("Usernames and passwords sent in-the-clear via FTP", packet, creds)
     # IMAP credentials
     if "LOGIN" in payload:
        creds = extract_imap_creds(payload)
        if creds:
            incident_number += 1
            print_incidents("Usernames and passwords sent in-the-clear via IMAP", packet, creds)
    except Exception as e:
        print(f"Error in check_credentials_and_nikto: {e}")

# Extract and decode HTTP Basic Authentication credentials
def extract_http_creds(payload):
    try:
     search = re.search(r'Authorization: Basic ([A-Za-z0-9+/=]+)', payload, re.IGNORECASE)
     if search:
        creds = base64.b64decode(search.group(1)).decode('latin-1')
        return f"(credentials) {creds}"
     return None
    except Exception as e:
        print(f"Error in extract_imap_creds {e}")


# Simple extraction of USER and PASS commands from FTP
ftp_sessions = {}  # Temporary storage for FTP sessions, because USER AND PASS ftp commands in separate packets in set1.pcap

def extract_ftp_creds(packet, payload):
    global ftp_sessions
    src_ip = packet[IP].src  # Identify the session by source IP
    try:
        if "USER" in payload:
            user_search = re.search(r'USER\s+(\S+)', payload)
            if user_search:
                ftp_sessions[src_ip] = {"username": user_search.group(1)}  # Store username
        if "PASS" in payload:
            pass_search = re.search(r'PASS\s+(\S+)', payload)
            if pass_search and src_ip in ftp_sessions:
                # Append password to the existing session
                ftp_sessions[src_ip]["password"] = pass_search.group(1)
                creds = f"(username: {ftp_sessions[src_ip]['username']}, password: {ftp_sessions[src_ip]['password']})"
                del ftp_sessions[src_ip]  # Clear session data after use
                return creds
    except Exception as e:
        print(f"Error in extract_ftp_creds: {e}")
    return None


# Simple extraction of LOGIN command from IMAP
def extract_imap_creds(payload):
    try:
     login_search = re.search(r'LOGIN (\S+) (\S+)', payload)
     if login_search:
        return f"(username: {login_search.group(1)}, password: {login_search.group(2)})"
     return None
    except Exception as e:
        print(f"Error in extract_imap_creds {e}")

# Prints alerts for incident types 
def print_incidents(incident_type, packet, additional_info=''):
    global incident_number
    try:
     src_ip = packet[IP].src
     dst_ip = packet[IP].dst
     dst_port = packet[TCP].dport if packet.haslayer(TCP) else 'N/A'
     print(f"ALERT #{incident_number}: {incident_type} is detected from {src_ip} to {dst_ip} (port {dst_port}) {additional_info}")
    except Exception as e:
        print(f"Error in print_incidents {e}")






# DO NOT MODIFY THE CODE BELOW
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
