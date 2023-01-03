import sys
import os
import re
import requests
import time

# Function for printing to stderr
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# Returns a string with the API key if it can find it in the file credentials/virustotal_api_key.txt
# relative to the script path.
def getAPIKey():
    dir_path = os.path.normpath(os.path.dirname(os.path.realpath(__file__)))
    path = dir_path + "/credentials/virustotal_api_key.txt"
    if os.path.exists(path):
        with open(path, "r") as file:
            api_key = file.read()
        return api_key
    else:
        eprint("Could not find api key at: " + path)
        exit(-2)

# Returns an array containing all IPv4 addresses found in the input file.
def readInputFile(input_file):
    ipv4_regex = "((?:[01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.(?:[01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.(?:[01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.(?:[01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5]))\n"
    
    if os.path.exists(input_file):
        with open(input_file, "r") as file:
            file_string = file.read()
            ips = re.findall(ipv4_regex, file_string)
        return ips
    else:
        eprint("Could not find input file at: " + input_file)
        exit(-2)

# Queries the Virustotal api and determines if the IP has been reported as malicious or suspicious by any vendors.
# Returns True if it has not been reported (i.e. it is clean) and False if not.
def ipIsClean(ip, api_key):
    headers = { "x-apikey": api_key }
    res = requests.get(url=f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)
    
    # Checking returned status code
    if res.status_code != 200:
        eprint(f"ERROR: received status code {res.status_code} when requesting ip {ip}")
    
    #print(f"Checking IP {ip}")
    res_json = res.json()
    statistics = res_json['data']['attributes']['last_analysis_stats']
    
    if statistics['malicious'] > 0 or statistics['suspicious'] > 0:
        return False
    else:
        return True

# Takes a list of IPs and writes them to ostream which is by default set to stdout, but could be a file stream.
def writeOutputFile(sus_ips, ostream=sys.stdout):
    for ip in sus_ips:
        print(ip, file=ostream)
    return

# Takes an input file, reads IPs from this file and checks them against Virustotal. Prints
# reported IPs to ostream.
def checkIPsFromFile(input_file, limited=False, ostream=sys.stdout):
    
    api_key = getAPIKey()
    ips = readInputFile(input_file)
    sus_ips = []
    sub_len = 4
    sleepy_time = 60
    
    if limited:
        ip_samples = [ips[x:x+sub_len] for x in range(0, len(ips), sub_len)]
        
        print(f"You are running with the throttled option which slows down the API calls. The estimated time for completion of the requested job is approximately {len(ip_samples)-1} minutes\n")
        
        for ip_sample in ip_samples[:-1]:
            for ip in ip_sample:
                if not ipIsClean(ip, api_key):
                    sus_ips.append(ip)
            time.sleep(sleepy_time)
        for ip in ip_samples[-1]:
            if not ipIsClean(ip, api_key):
                sus_ips.append(ip)
    else:
        for ip in ips:
            if not ipIsClean(ip, api_key):
                sus_ips.append(ip)
    
    if len(sus_ips) <= 0:
        print("Hurray! No malicious IPs found")
    else:
        print("Suspiscious / malicious IPs detected:")
        for ip in sus_ips:
            print(ip)
        print()
        
        if ostream != sys.stdout:
            writeOutputFile(sus_ips, ostream)
            
    return