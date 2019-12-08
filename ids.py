#! /usr/bin/env python2.7

import multiprocessing, os
import random
import re
from scapy.all import *
from netfilterqueue import NetfilterQueue


RANDOM_CHARS = 'abcdefghijklmnopqrstuvwxyz1234567890'
RAND_MIN_LEN = 7
RAND_MAX_LEN = 15

DNSServers = {}
class DNSServer:
    ip = ''
    charBin = {}
    queries = []
    def __init__(self, ip):
        self.ip = ip
        for letter in RANDOM_CHARS:        
            self.charBin[letter] = 0

class Query:
    domain = ''
    record = ''
    def __init__(self, Domain, Record):
        self.domain = Domain
        self.record = Record


def letterCounter(ip, name):
    re.sub(r'\..*', '', name)
#    re.sub(r'[/,+]','',name)
    for letter in name:
        if letter in DNSServers[ip].charBin:
            DNSServers[ip].charBin[letter] += 1


def runChecks():
    for dns in DNSServers.values():
        if len(dns.queries)>10:
            dns.queries.pop(0)
	repeatedRecord = False
	#Check if records match for different domains
        for i in range(len(dns.queries)):
            for j in range(i+1, len(dns.queries)):
                if(dns.queries[i].domain != dns.queries[j].domain):
                    if(dns.queries[i].record == dns.queries[j].record):
                        repeatedRecord = True
                        #wowwee that shouldn't happen
	if repeatedRecord:
	    print("Record repeated, dns compromised")
        #Okay now check if the charBins are unreasonable.
        average = 0
        var = 0
        for letter in RANDOM_CHARS:
            average += dns.charBin[letter]
        average = average/36.0
        
        for letter in RANDOM_CHARS:
            var += (dns.charBin[letter]-average)**2        
        var = (var/35)**.5
        coeff = var/average
        if average > 5 and coeff<.4:
            print("average: "+str(average)+" Std: "+str(var)) 
        
def read(packet):
    # Convert the raw packet to a scapy compatible string
    scapy_pkt = IP(packet.get_payload())
    packetIP = str(scapy_pkt[IP].src)
    
    # Read packet payload and run command if asked
    if scapy_pkt.haslayer(DNSRR):
        # If the packet is a DNS Resource Record (DNS reply)
        try:
	    domain = scapy_pkt[DNS].qd.qname
            record = scapy_pkt[DNS].an.rdata
            newQuery = Query(domain, record)
	    print("1")
            if packetIP not in DNSServers:
		print("2")
                newDNSServer = DNSServer(packetIP)
                DNSServers[packetIP] = newDNSServer
            DNSServers[packetIP].queries.append(newQuery)
            print("3")
            letterCounter(packetIP, domain)
            runChecks()
        except IndexError:
            # Not UDP packet, this can be IPerror/UDPerror packets
            pass

    # Accept the packet
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
    
    # Join processes and remove iptables rule
    os.system('iptables -D FORWARD -p udp -m udp --sport 53 -j NFQUEUE --queue-num 1')
    print('[*] iptables rule removed')
