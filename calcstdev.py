#! /usr/bin/env python2.7

import os, re, csv, random

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

if __name__ == "__main__":
    # Initialize charscount dictionary
    for c in domainchars:
        charscount[c] = 0

    if not getcsv():
        print('Failed to get Alexa 1 million list')
        exit(9)

    # Total characters counted
    totalchars = 0

    # Open the CSV
    with open('top-1m.csv') as csvfile:
        # Count occurrences of each char in domainchars in Alexa 1m list
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
            # Get domain name minus all characters after first '.'
            domain = re.sub(r'\..*', '', row[1])
            #domain = random.choice(domainchars)
            for c in domain:
                if c in domainchars:
                    totalchars += 1
                    charscount[c] += 1
                    
    # Calculate average occurence of each char
    average = totalchars / len(domainchars)
    
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
