
import base64
import socket
from datetime import datetime, date
import os
import html.parser

try:
  import requests
except ImportError:
  print "Trying to Install required module: requests\n"
  os.system('python -m pip install requests')
# -- above lines try to install requests module if not present
# -- if all went well, import required module again ( for global access)
import requests

from ipwhois import IPWhois

VT_API_KEY = 'e3cf255cf4c5cf3d5438189b28c91fe91796ed569f6e4a39bed3834e93fba13c'
AB_API_KEY = '7664fdaa5ee24939ea1f2fa2c39ca21f9d0530e58b030d8bf92d714ac89eba6104f0b1df95d495a9'

def checkIP(ip):
    w = IPWhois(ip)
    w = w.lookup_whois()
    addr = str(w['nets'][0]['address'])
    addr = addr.replace('\n', ', ')
    IP = socket.gethostbyname(ip)
    now = datetime.now()
    today = now.strftime("%m-%d-%Y")

    print("\nBrief Info:")
    print("  CIDR:      " + str(w['nets'][0]['cidr']))
    print("  Name:      " + str(w['nets'][0]['name']))
    print("  Range:     " + str(w['nets'][0]['range']))
    print("  Descr:     " + str(w['nets'][0]['description']))
    print("  Country:   " + str(w['nets'][0]['country']))
    print("  State:     " + str(w['nets'][0]['state']))
    print("  City:      " + str(w['nets'][0]['city']))
    print("  Post Code: " + str(w['nets'][0]['postal_code']))
    print("  Created:   " + str(w['nets'][0]['created']))
    print("  Updated:   " + str(w['nets'][0]['updated']))

    print("\n VirusTotal:")

    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': VT_API_KEY, 'resource': IP}
    response = requests.get(url, params=params)
    pos = 0 # Total positives found in VT
    tot = 0 # Total number of scans

    if response.status_code == 200:
        try:
            print(response.json())
            result = response.json()

            for each in result:
                tot = result['total']

                if result['positives'] != 0:
                    pos = pos + 1

            print("   No of Databases Checked: " + str(tot))
            print("   No of Reportings: " + str(pos))

        except:
            print('error')
    else:
        print("error 2")

    try:
        TOR_URL = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"
        req = requests.get(TOR_URL)

        print("\n TOR: ")

        if req.status_code == 200:
            tl = req.text.split('\n')
            count = 0

            for i in tl:
                if IP == i:
                    print("  " + i + " is a TOR Exit Node")
                    count = count + 1
            if count == 0:
                print("  " + IP + " is NOT a TOR Exit Node")

    except:
        print("There is an error with checking for Tor exit nodes:\n")

    print("\n ABUSEIPDB Report:")

    try:
        AB_URL = 'https://api.abuseipdb.com/api/v2/check'
        days = '180'

        query = {
            'ipAddress': IP,
            'maxAgeInDays': days
        }

        headers = {
            'Accept': 'application/json',
            'Key': AB_API_KEY
        }
        response = requests.request(method='GET', url=AB_URL, headers=headers, params=query)
        if response.status_code == 200:
            req = response.json()

            print("   IP:          " + str(req['data']['ipAddress']))
            print("   Reports:     " + str(req['data']['totalReports']))
            print("   Abuse Score: " + str(req['data']['abuseConfidenceScore']) + "%")
            print("   Last Report: " + str(req['data']['lastReportedAt']))

        else:
            print("   Error")
    except:
        print('   IP Not Found')

ip = input("enter ip:")
checkIP(ip)

def main():
   pass

if __name__ == '__main__':
    main()