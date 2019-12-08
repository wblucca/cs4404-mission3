#! /usr/bin/env python2.7

import multiprocessing, os
import random
import re
from scapy.all import *
from netfilterqueue import NetfilterQueue

B64_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+'
NUM_ASCII = 256
# Number of replies to hold on to for analysis
MAX_REPLIES = 10

# Minimum average to block for failing random analysis
TXT_MIN_AVG = 3
# Maximum CV to count as random analysis failure
TXT_MAX_CV = 0.4

prevReply = ''

blocked_ips = []
dns_servers = {}


class DNSServer:
    """Class for storing info on servers that have sent DNS replies
    """

    ip = ''
    charbin = {}
    replies = []

    def __init__(self, ip):
        self.ip = ip
        for i in range(NUM_ASCII):
            c = chr(i)
            self.charbin[c] = 0


class Reply:
    """A DNS reply
    """

    domain = ''
    record = ''

    def __init__(self, domain, record):
        self.domain = domain
        self.record = record


def count_letters(ip, data):
    """Add occurrences for each letter in data to the DNS server's char bin
    """
    global dns_servers

    # Get DNS server
    dns_server = dns_servers[ip]

    # Add letter occurrences
    for letter in data:
        dns_server.charbin[letter] += 1


def run_checks(dns):
    """Analyze recorded DNS data for malicious traffic, blocking IP if found
    """
    global dns_servers

    if len(dns.replies) > MAX_REPLIES:
        dns.replies.pop(0)

    #Check if records match for different domains
    repeated_record = False
    for i in range(len(dns.replies)):
        for j in range(i + 1, len(dns.replies)):
            if dns.replies[i].domain != dns.replies[j].domain:
                if dns.replies[i].record == dns.replies[j].record:
                    repeated_record = True

    if repeated_record:
        print("Record repeated, DNS compromised")
        # blocked_ips.append(dns.ip)

    # Now check if the charbins are unreasonable (i.e. randomized characters)
    totalchars = 0
    totalsqrdiff = 0
    for letter in B64_CHARS:
        totalchars += dns.charbin[letter]
    average = totalchars / float(len(B64_CHARS))
    
    for letter in B64_CHARS:
        totalsqrdiff += (dns.charbin[letter] - average) ** 2
    stddev = (totalsqrdiff / (len(B64_CHARS) - 1)) ** 0.5

    if average != 0:
        cv = stddev / average
    else:
        cv = 0

    print("Average: "+str(average) + " CV: "+str(cv))
    
    # Check for malicious data
    if average > TXT_MIN_AVG and cv < TXT_MAX_CV:
        print('Bad domain CV, DNS compromised')
        blocked_ips.append(dns.ip)


def read(packet):
    """Records the packet's information and checks DNS servers validity
    """
    global dns_servers, prevReply

    # Convert the raw packet to a scapy compatible string
    scapy_pkt = IP(packet.get_payload())
    packet_ip = str(scapy_pkt[IP].src)
    
    # If the packet is a DNS Resource Record (DNS reply)
    if scapy_pkt.haslayer(DNSRR):
        print('[+] Got DNS packet')

        try:
            # Get DNS data
            domain = scapy_pkt[DNS].qd.qname
            record = scapy_pkt[DNS].an.rdata
            new_reply = Reply(domain, record)

            # Create DNS server object if this reply is from a new server
            if packet_ip not in dns_servers:
                new_dns_server = DNSServer(packet_ip)
                dns_servers[packet_ip] = new_dns_server
            dns_server = dns_servers[packet_ip]

            # Add the reply object
            dns_server.replies.append(new_reply)

            print('[+] TXT: "' + str(record) + '"   IP: "' + str(packet_ip) + '"')

            # Remove everything after first '.' and total up the characters
	    if record != prevReply:
                count_letters(packet_ip, record)
	    prevReply = record
            # Verify this DNS server
            run_checks(dns_server)

        except IndexError:
            # Not UDP packet, this can be IPerror/UDPerror packets
            pass

    # Accept/Drop the packet
    if packet_ip in blocked_ips:
        packet.drop()
    else:
        packet.accept()

nfqueue = NetfilterQueue()
def run_nfqueue():
    try:
        print('[*] NFQUEUE running')
        nfqueue.run()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    # Setup the iptables rule and nfqueue
    os.system('iptables -A FORWARD -p udp -m udp --sport 53 -j NFQUEUE --queue-num 1')
    print('[*] iptables rule created')
    nfqueue.bind(1, read)  # iptables queue number and callback function
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        pass
    
    # Remove iptables rule
    os.system('iptables -D FORWARD -p udp -m udp --sport 53 -j NFQUEUE --queue-num 1')
    print('[*] iptables rule removed')
