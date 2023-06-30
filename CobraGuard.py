import scapy.all as scapy

# Create an empty dictionary to keep track of the ARP table.
arp_dict = {}

def handle_packet(packet):
    # Is the packet an ARP packet?
    if packet.haslayer(scapy.ARP):
        # Is it an ARP response (is-at), not a request (who-has)?
        if packet[scapy.ARP].op == 2:
            print("Detected ARP Response: IP {} is associated with MAC {}".format(packet[scapy.ARP].psrc, packet[scapy.ARP].hwsrc))
            
            # Do we have an entry for this IP in our table?
            if packet[scapy.ARP].psrc in arp_dict:
                # If the MAC address has changed, we might be under attack.
                if arp_dict[packet[scapy.ARP].psrc] != packet[scapy.ARP].hwsrc:
                    print("Potential ARP Spoofing Attack!")
                    print("Recorded MAC for IP {} was {}, but a packet claims it's {}".format(packet[scapy.ARP].psrc, arp_dict[packet[scapy.ARP].psrc], packet[scapy.ARP].hwsrc))
            else:
                # If we don't have an entry for this IP, let's add it to our ARP table.
                arp_dict[packet[scapy.ARP].psrc] = packet[scapy.ARP].hwsrc

# Let's start listening to the network traffic.
scapy.sniff(prn=handle_packet, filter="arp", store=0)
