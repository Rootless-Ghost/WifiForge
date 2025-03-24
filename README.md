# Wireless Network Security Analyzer

A tool for analyzing and assessing the security of wireless networks that you own or have permission to test.

## Features

- Passive scanning of nearby wireless networks
- Detection of common security vulnerabilities
- Detailed security assessment reports
- CSV export of scan results

## Requirements

- Python 3
- Root privileges (needed for monitor mode)
- Wireless interface that supports monitor mode

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/wifi-security-analyzer.git
cd wifi-security-analyzer

# Install requirements
pip install -r requirements.txt

# Basic network scan
sudo python3 wifi_security_analyzer.py -i wlan0 -t 30

# Security check for a specific network
sudo python3 wifi_security_analyzer.py -i wlan0 -t 30 --check --bssid 00:11:22:33:44:55

# Save results to CSV
sudo python3 wifi_security_analyzer.py -i wlan0 -t 30 -o scan_results.csv
