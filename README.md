# CobraGuard: A Simple Intrusion Prevention System

# Introduction
CobraGuard is a simple Intrusion Prevention System (IPS) written in Python using the Scapy library. The primary goal of is to detect ARP spoofing attacks, which are commonly used in network intrusions.

## Note
CobraGuard is a demonstration of an IPS. Real-world intrusion prevention systems are much more complex and sophisticated. 

## Installation
CobraGuard has only one dependency, Scapy. You can install it with pip:

### pip install scapy

After installing Scapy, you can download GuardNet and run it directly.

## Usage
To start CobraGuard, simply navigate to its directory and run the script:

### python guardnet.py

Once started, CobraGuard will begin sniffing network traffic for ARP packets. When an ARP response packet is detected, it adds the IP-MAC pair to its internal ARP table. If it detects an ARP response from the same IP but with a different MAC address, it will display a warning message, suggesting a potential ARP spoofing attack.

## Contributing
If you wish to contribute to CobraGuard, I welcome your input! Please feel free to fork the repository and submit pull requests. You can also open issues if you find bugs or have suggestions for improvements.

## Disclaimer
CobraGuard is intended for educational purposes. It should not be used as a primary security tool for any network. Always use professional-grade security tools and practices for protection.

## License
CobraGuard is released under the MIT license. See LICENSE for more details
