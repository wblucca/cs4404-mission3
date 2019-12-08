#! /usr/bin/env python2.7

import os, sys, re, csv

goodchars = 'abcdefghijklmnopqrstuvwxyz0123456789'
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
    pass


if __name__ == "__main__":
    # Check args
    if len(sys.argv) == 1:
        print('\nUsage:  calc-cv.py numsites [--txt]\n')
        exit(1)

    # Download CSV data from Alexa
    if not getcsv():
        print('Failed to get Alexa 1 million list')
        exit(9)

    numsites = int(sys.argv[1])

    # Initialize charscount dictionary
    for c in goodchars:
        charscount[c] = 0

    # Total characters counted
    totalchars = 0

    # Open the CSV
    with open('top-1m.csv') as csvfile:
        # Setup CSV for reading
        readCSV = csv.reader(csvfile, delimiter=',')

        # Count occurrences of each char in goodchars in Alexa 1m list
        for i in range(numsites):
            # Get next row in CSV
            try:
                row = readCSV.next()
            except StopIteration:
                print(str(numsites) + ' is too many sites')
                break

            if len(sys.argv) > 2 and sys.argv[2] == '--txt':
                name = gettxt(row[1])
            else:
                # Get domain name minus all characters after first '.'
                name = re.sub(r'\..*', '', row[1])

            for c in name:
                if c in goodchars:
                    totalchars += 1
                    charscount[c] += 1
                    
    # Calculate average occurence of each char
    average = totalchars / float(len(goodchars))
    
    # Calculate std deviation and coefficient of variation
    totalsqrdiff = 0
    for c in goodchars:
        totalsqrdiff += (charscount[c] - average) ** 2
        print(c + ': ' + str(charscount[c]))
    stddev = (totalsqrdiff / (len(goodchars) - 1)) ** 0.5
    cv = stddev / average

    # Print info from data
    print('Using chars: ' + goodchars)
    print('Characters counted: ' + str(totalchars))
    print('Average character count: ' + str(average))
    print('Stdev:\t' + str(stddev))
    print('CV:\t' + str(cv))
