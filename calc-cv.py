#! /usr/bin/env python2.7

import os, sys, re, csv
from subprocess import check_output

domainchars = 'abcdefghijklmnopqrstuvwxyz0123456789'
charscount = {}


def getcsv():
    # Get CSV zip file
    if os.system('curl http://s3.amazonaws.com/alexa-static/top-1m.csv.zip --output alexa-1m.csv.zip > /dev/null') != 0:
        return False
    # Unzip to alexa-1m.csv
    if os.system('unzip -f alexa-1m.csv.zip > /dev/null') != 0:
        return False

    # No errors
    return True


def gettxt(domain):
    # Get stdout from nslookup for TXT record
    out = check_output(['nslookup', '-q=txt', domain])

    txts = []

    # Parse all the output
    for line in out.splitlines():
        txt = re.sub(r'.*text = "', '', line)
        txts.append(txt[:-1])
        print(txt)
    
    # Return all of the found record data
    return txts


def analyzedomain():
    # Initialize charscount dictionary
    for c in range(len(domainchars)):
        charscount[c] = 0

    # Total characters counted
    totalchars = 0

    # Open the CSV
    with open('top-1m.csv') as csvfile:
        # Setup CSV for reading
        readCSV = csv.reader(csvfile, delimiter=',')

        # Count occurrences of each char in domainchars in Alexa 1m list
        for i in range(numsites):
            # Get next row in CSV
            try:
                row = readCSV.next()
            except StopIteration:
                print(str(numsites) + ' is too many sites')
                break

            # Get domain name minus all characters after first '.'
            name = re.sub(r'\..*', '', row[1])

            # Add character occurrences to totals
            for c in name:
                if c in domainchars:
                    totalchars += 1
                    charscount[c] += 1
                    
    # Calculate average occurence of each char
    average = totalchars / float(len(domainchars))
    
    # Calculate std deviation and coefficient of variation
    totalsqrdiff = 0
    for c in domainchars:
        totalsqrdiff += (charscount[c] - average) ** 2
        print(c + ': ' + str(charscount[c]))
    stddev = (totalsqrdiff / (len(domainchars) - 1)) ** 0.5
    cv = stddev / average

    # Print info from data
    print('Using chars: ' + domainchars)
    print('Characters counted: ' + str(totalchars))
    print('Average character count: ' + str(average))
    print('Stdev:\t' + str(stddev))
    print('CV:\t' + str(cv))


def analyzetxt():
    # Initialize charscount dictionary
    for i in range(256):
        c = chr(i)
        charscount[c] = 0

    # Total characters counted
    totalchars = 0

    # Open the CSV
    with open('top-1m.csv') as csvfile:
        # Setup CSV for reading
        readCSV = csv.reader(csvfile, delimiter=',')

        # Count occurrences of each char in domainchars in Alexa 1m list
        for i in range(numsites):
            # Get next row in CSV
            try:
                row = readCSV.next()
            except StopIteration:
                print(str(numsites) + ' is too many sites')
                break

            # Get data in TXT records of domain
            txts = gettxt(row[1])

            # Add character occurrences to totals
            for txt in txts:
                for c in txt:
                    totalchars += 1
                    charscount[c] += 1
                    
    # Calculate average occurence of each char
    average = totalchars / 256.0
    
    # Calculate std deviation and coefficient of variation
    totalsqrdiff = 0
    for i in range(256):
        c = chr(i)
        totalsqrdiff += (charscount[c] - average) ** 2
        print(c + ': ' + str(charscount[c]))
    stddev = (totalsqrdiff / (len(domainchars) - 1)) ** 0.5
    cv = stddev / average

    # Print info from data
    print('Using chars: ' + ''.join(chr(i) for i in range(256)))
    print('Characters counted: ' + str(totalchars))
    print('Average character count: ' + str(average))
    print('Stdev:\t' + str(stddev))
    print('CV:\t' + str(cv))


if __name__ == "__main__":
    # Check args
    if len(sys.argv) == 1:
        print('\nUsage:  calc-cv.py numsites [--txt]\n')
        exit(1)

    # Download CSV data from Alexa
    if '--no-dl' not in sys.argv:
        print('fdsfjdsfs')
        if not getcsv():
            print('Failed to get Alexa 1 million list')
            exit(9)

    numsites = int(sys.argv[1])

    if '--txt' in sys.argv:
        analyzetxt()
    else:
        analyzedomain()
