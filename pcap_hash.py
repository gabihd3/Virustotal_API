import re
import requests

f = open("/The/Correct/Path/hashes.txt")
test = []
for i in f.readlines():
    fa = re.findall("[A-Fa-f0-9]{64}", i) # get all hashes based on a regex
    test.append(fa)

empty = [i[0] for i in test]
empty = list(set(empty)) # Delete duplicates

if len(empty) == 0:
    print("No hashes found in the file")

headers = {
    'Accept':'application/json',
    'X-Apikey': 'insert your VT api key'
}

def lookup_hash(dom):
    for i in dom:
        url = f'https://www.virustotal.com/api/v3/files/{i}'
        respcode = requests.get(url, headers = headers).status_code
        if respcode !=  200:
            print(i, respcode)
        else:
            response = requests.get(url, headers = headers).json()
            report = (response['data']['attributes']['last_analysis_stats']['malicious']) # Check for VT hits from the json response
            if report > 0: # If any hits, print them, pass otherwise
                print(f'-{i}: {report} vendors')
            else:
                pass 
lookup_hash(empty)


