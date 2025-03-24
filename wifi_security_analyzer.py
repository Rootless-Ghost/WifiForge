#!/usr/bin/env python3
"""
Wireless Network Security Analyzer
A tool for analyzing and assessing the security of wireless networks
that you own or have permission to test.
"""

import os
import time
import argparse
import csv
from datetime import datetime
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sniff
from tabulate import tabulate

# Check for root privileges
if os.geteuid() != 0:
    print("This script must be run as root to put the network interface in monitor mode.")
    exit(1)

# Global variables
networks = {}
vulnerabilities = {
    "WEP": "Deprecated encryption that can be easily cracked",
    "Open": "No encryption - all traffic can be intercepted",
    "WPA": "Older encryption with known vulnerabilities",
    "WPA2_TKIP": "WPA2 with TKIP has known weaknesses",
    "Hidden_SSID": "Hidden networks can be easily discovered"
}

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Wireless Network Security Analyzer')
    parser.add_argument('-i', '--interface', required=True, help='Wireless interface to use')
    parser.add_argument('-t', '--time', type=int, default=60, help='Scan time in seconds (default: 60)')
    parser.add_argument('-o', '--output', help='Output file for scan results (CSV format)')
    parser.add_argument('--check', action='store_true', help='Check security of your own network')
    parser.add_argument('--bssid', help='BSSID of your network to check (required with --check)')
    return parser.parse_args()

def enable_monitor_mode(interface):
    """Enable monitor mode on the wireless interface."""
    print(f"[*] Enabling monitor mode on {interface}")
    os.system(f"sudo ip link set {interface} down")
    os.system(f"sudo iw {interface} set monitor control")
    os.system(f"sudo ip link set {interface} up")
    print(f"[+] Monitor mode enabled on {interface}")

def disable_monitor_mode(interface):
    """Disable monitor mode on the wireless interface."""
    print(f"[*] Disabling monitor mode on {interface}")
    os.system(f"sudo ip link set {interface} down")
    os.system(f"sudo iw {interface} set type managed")
    os.system(f"sudo ip link set {interface} up")
    print(f"[+] Monitor mode disabled on {interface}")

def packet_handler(packet):
    """Process captured packets to extract network information."""
    if packet.haslayer(Dot11Beacon):
        # Extract the MAC address of the network
        bssid = packet[Dot11].addr2
        if bssid not in networks:
            networks[bssid] = {
                "ssid": "",
                "channel": "",
                "encryption": "",
                "signal_strength": "",
                "first_seen": datetime.now(),
                "last_seen": datetime.now(),
                "vulnerabilities": []
            }
        else:
            networks[bssid]["last_seen"] = datetime.now()
        
        # Extract network name (SSID)
        try:
            networks[bssid]["ssid"] = packet[Dot11Elt].info.decode('utf-8')
            if not networks[bssid]["ssid"]:
                networks[bssid]["ssid"] = "<Hidden SSID>"
                if "Hidden_SSID" not in networks[bssid]["vulnerabilities"]:
                    networks[bssid]["vulnerabilities"].append("Hidden_SSID")
        except:
            networks[bssid]["ssid"] = "<Decode Error>"
        
        # Extract signal strength if available
        if packet.haslayer(RadioTap):
            networks[bssid]["signal_strength"] = f"{packet[RadioTap].dBm_AntSignal} dBm"
        
        # Extract channel information
        for element in packet.iterpayload():
            if isinstance(element, Dot11Elt) and element.ID == 3:
                networks[bssid]["channel"] = ord(element.info)
                break
        
        # Determine encryption type
        encryption_type = "Open"
        
        # Check for encryption
        capability = packet[Dot11Beacon].cap
        if capability & 0x10:  # Privacy bit set
            encryption_type = "WEP"  # Default to WEP
            
            # Look for RSN (WPA2) information
            rsn_info = None
            for element in packet.iterpayload():
                if isinstance(element, Dot11Elt) and element.ID == 48:
                    rsn_info = element.info
                    encryption_type = "WPA2"
                    break
                    
            # Look for WPA information
            if not rsn_info:
                for element in packet.iterpayload():
                    if isinstance(element, Dot11Elt) and element.ID == 221 and element.info.startswith(b'\x00\x50\xf2\x01\x01\x00'):
                        encryption_type = "WPA"
                        break
        
        networks[bssid]["encryption"] = encryption_type
        
        # Check for vulnerabilities based on encryption type
        if encryption_type == "Open" and "Open" not in networks[bssid]["vulnerabilities"]:
            networks[bssid]["vulnerabilities"].append("Open")
        elif encryption_type == "WEP" and "WEP" not in networks[bssid]["vulnerabilities"]:
            networks[bssid]["vulnerabilities"].append("WEP")
        elif encryption_type == "WPA" and "WPA" not in networks[bssid]["vulnerabilities"]:
            networks[bssid]["vulnerabilities"].append("WPA")

def display_networks():
    """Display discovered networks in a formatted table."""
    table_data = []
    for bssid, data in networks.items():
        vulns = ", ".join(data["vulnerabilities"]) if data["vulnerabilities"] else "None detected"
        table_data.append([
            bssid,
            data["ssid"],
            data["channel"],
            data["encryption"],
            data["signal_strength"],
            vulns
        ])
    
    print("\n" + tabulate(table_data, headers=["BSSID", "SSID", "Channel", "Encryption", "Signal", "Vulnerabilities"], tablefmt="grid"))

def save_to_csv(filename):
    """Save network scan results to a CSV file."""
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["BSSID", "SSID", "Channel", "Encryption", "Signal Strength", "First Seen", "Last Seen", "Vulnerabilities"])
        
        for bssid, data in networks.items():
            writer.writerow([
                bssid,
                data["ssid"],
                data["channel"],
                data["encryption"],
                data["signal_strength"],
                data["first_seen"].strftime("%Y-%m-%d %H:%M:%S"),
                data["last_seen"].strftime("%Y-%m-%d %H:%M:%S"),
                ", ".join(data["vulnerabilities"])
            ])
    
    print(f"[+] Results saved to {filename}")

def security_check(bssid):
    """Perform a detailed security check on a specific network."""
    if bssid not in networks:
        print(f"[!] Network with BSSID {bssid} not found in scan results")
        return
    
    network = networks[bssid]
    print("\n" + "=" * 50)
    print(f"Security Assessment for: {network['ssid']} ({bssid})")
    print("=" * 50)
    
    # Basic information
    print(f"Channel: {network['channel']}")
    print(f"Encryption: {network['encryption']}")
    
    # Vulnerability assessment
    print("\nVulnerability Assessment:")
    if not network["vulnerabilities"]:
        print("✅ No common vulnerabilities detected")
    else:
        for vuln in network["vulnerabilities"]:
            print(f"❌ {vuln}: {vulnerabilities[vuln]}")
    
    # Recommendations
    print("\nRecommendations:")
    if "Open" in network["vulnerabilities"]:
        print("- Enable WPA2/WPA3 encryption with a strong password")
    elif "WEP" in network["vulnerabilities"]:
        print("- Upgrade to WPA2 or WPA3 encryption")
    elif "WPA" in network["vulnerabilities"]:
        print("- Upgrade to WPA2 or WPA3 encryption")
    
    if "Hidden_SSID" in network["vulnerabilities"]:
        print("- Hiding your SSID doesn't provide real security; use strong encryption instead")
    
    print("- Use a strong, unique password of at least 12 characters")
    print("- Enable WPA3 if your devices support it")
    print("- Regularly update router firmware")
    print("- Consider setting up a guest network for visitors")
    print("=" * 50)

def main():
    """Main function to run the wireless network analyzer."""
    args = parse_arguments()
    
    try:
        # Setup monitor mode
        enable_monitor_mode(args.interface)
        
        print(f"[*] Starting wireless network scan on {args.interface} for {args.time} seconds...")
        print("[*] Press Ctrl+C to stop the scan early")
        
        # Start packet sniffing
        sniff(iface=args.interface, prn=packet_handler, timeout=args.time)
        
        # Display results
        print(f"\n[+] Scan completed. Found {len(networks)} networks.")
        display_networks()
        
        # Check security of a specific network if requested
        if args.check and args.bssid:
            security_check(args.bssid)
        
        # Save results to CSV if output file specified
        if args.output:
            save_to_csv(args.output)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
    finally:
        # Cleanup and restore interface
        disable_monitor_mode(args.interface)

if __name__ == "__main__":
    main()