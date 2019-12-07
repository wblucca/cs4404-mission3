#! /usr/bin/env python2.7

import os, csv

domainchars = 'abcdefghijklmnopqrstuvwxyz0123456789'
charscount = {}

def getcsv():
    # Get CSV zip file
    if os.system('curl http://s3.amazonaws.com/alexa-static/top-1m.csv.zip --output alexa-1m.csv.zip') != 0:
        return false
    # Unzip to alexa-1m.csv
    if os.system('unzip alexa-1m.csv.zip') != 0:
        return false

    # No errors
    return true

if __name__ == "__main__":
    # Initialize charscount dictionary
    for c in domainchars:
        charscount[c] = 0
    
    print('Using chars: ' + domainchars)

    if not getcsv():
        print('Failed to get Alexa 1 million list')
        exit(9)

    # Total characters counted
    totalchars = 0

    # Open the CSV
    with open('alexa-1m.csv') as csvfile:
        # Count occurrences of each char in domainchars in Alexa 1m list
        for row in csvfile:
            # Get domain name minus all characters after first '.'
            domain = re.sub(r'\..*', '', row[1])
            for c in domain:
                if c in domainchars:
                    totalchars += 1
                    charscount[c] += 1
                else:
                    print(c)
                    
    # Calculate average occurence of each char
    average = totalchars / len(domainchars)

    # Calculate std deviation
    totalsqrdiff = 0
    for c in domainchars:
        totalsqrdiff += (charscount[c] - average) ** 2
    stddev = (totalsqrdiff / (len(domainchars) - 1)) ** 0.5

    print('Standard deviation for top 1 million sites: ' + str(stddev))
    return stddev
