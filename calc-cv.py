#! /usr/bin/env python2.7

import os, sys, re, csv
from subprocess import check_output

# Record info to this array of strings. Write to stdout or file after execution
out = []

DOMAIN_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'
B64_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+'

# Dictionary for counting char occurrences
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
    nslookup_output = check_output(['nslookup', '-q=txt', domain])
    record('Domain: ' + domain)

    txts = []

    # Parse all the output
    for line in nslookup_output.splitlines():
        matches = re.search(r'(?<=text = ").+"', line)
        if matches:
            txt = matches.group(0)[:-2]
            txts.append(txt)
            record('TXT data: ' + txt)
    record('')

    # Return all of the found record data
    return txts


def analyzedomain():
    # Initialize charscount dictionary
    for c in DOMAIN_CHARS:
        charscount[c] = 0

    # Total characters counted
    totalchars = 0

    # Open the CSV
    with open('top-1m.csv') as csvfile:
        # Setup CSV for reading
        readCSV = csv.reader(csvfile, delimiter=',')

        # Count occurrences of each char in DOMAIN_CHARS in Alexa 1m list
        for i in range(numsites):
            # Get next row in CSV
            try:
                row = readCSV.next()
            except StopIteration:
                print(str(numsites) + ' is too many sites')
                break

            # Get domain name minus all characters after first '.'
            name = re.sub(r'\..*', '', row[1])
            record('Domain: ' + name)

            # Add character occurrences to totals
            for c in name:
                if c in DOMAIN_CHARS:
                    totalchars += 1
                    charscount[c] += 1
                    
    # Calculate average occurence of each char
    average = totalchars / float(len(DOMAIN_CHARS))
    
    # Calculate std deviation and coefficient of variation
    totalsqrdiff = 0
    for c in DOMAIN_CHARS:
        totalsqrdiff += (charscount[c] - average) ** 2
        record(c + ': ' + str(charscount[c]))
    stddev = (totalsqrdiff / (len(DOMAIN_CHARS) - 1)) ** 0.5
    if average != 0:
        cv = stddev / average
    else:
        cv = 0

    # Record info from data
    record('Using chars: ' + DOMAIN_CHARS)
    record('Characters counted: ' + str(totalchars))
    record('Average character count: ' + str(average))
    record('Stdev:\t' + str(stddev))
    record('CV:\t' + str(cv))


def analyzetxt():
    # Initialize charscount dictionary
    for c in B64_CHARS:
        charscount[c] = 0

    # Total characters counted
    totalchars = 0

    # Open the CSV
    with open('top-1m.csv') as csvfile:
        # Setup CSV for reading
        readCSV = csv.reader(csvfile, delimiter=',')

        # Count occurrences of each char in DOMAIN_CHARS in Alexa 1m list
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
                    if c in B64_CHARS:
                        totalchars += 1
                        charscount[c] += 1
                    
    # Calculate average occurence of each char
    average = totalchars / float(len(B64_CHARS))
    
    # Calculate std deviation and coefficient of variation
    totalsqrdiff = 0
    for c in B64_CHARS:
        totalsqrdiff += (charscount[c] - average) ** 2
        record(c + ': ' + str(charscount[c]))
    stddev = (totalsqrdiff / (len(DOMAIN_CHARS) - 1)) ** 0.5
    if average != 0:
        cv = stddev / average
    else:
        cv = 0

    # Record info from data
    record('Using chars: ' + B64_CHARS)
    record('Characters counted: ' + str(totalchars))
    record('Average character count: ' + str(average))
    record('Stdev:\t' + str(stddev))
    record('CV:\t' + str(cv))


def record(data):
    global out
    out.append(data + '\n')


if __name__ == "__main__":
    # Check args
    if len(sys.argv) == 1:
        print('\nUsage:  calc-cv.py NUMSITES [--txt] [-o OUTPUTFILE]\n')
        exit(1)

    # Download CSV data from Alexa
    if '--no-dl' not in sys.argv:
        if not getcsv():
            print('Failed to get Alexa 1 million list')
            exit(9)

    numsites = int(sys.argv[1])

    # Read TXT records or domain names
    if '--txt' in sys.argv:
        analyzetxt()
    else:
        analyzedomain()
    
    # Record data to stdout or a file
    if '-o' in sys.argv:
        o_index = sys.argv.index('-o')
        filename = sys.argv[o_index + 1]
        with open(filename, 'w') as outputfile:
            for line in out:
                outputfile.write(line)
    else:
        print(''.join(out))
