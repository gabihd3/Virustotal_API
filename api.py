import os
import json
import requests 

api_key = input("What's the key? ")

headers = {
    "Accept": "application/json",
    "X-Apikey": api_key
    }

list_ips = ["195.54.160.149", "165.227.239.108", "167.71.13.196", "84.70.180.143", "98.0.242.10"]
list_hashes = ["ef8b5595808021dff2f1013a0b06275945021a7e871e6776c48523e950e01d4f", "9841973ca2ea111ec8378ba3ac08d4056ac9bdbae3f50b14de1872b7a6419b2c"]

results = []
def find_ips(ips):
    for i in ips:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{i}"
        response = requests.get(url, headers=headers).json()
        report = (i, response["data"]["attributes"]["last_analysis_stats"]["malicious"])
        results.append(report)
        #selection = [i[-1] for i in results if i[-1]>0]
    return results
#print("IPs:", find_ips(list_ips))
#all = requests.get(url, headers = headers)
#print(all.text)

def find_hashes(hash):
    resultados_hashes = []
    for i in hash:
        url_hash = f"https://www.virustotal.com/api/v3/files/{i}"
        try:
            response = requests.get(url_hash, headers=headers).json()
            report = (i, response["data"]["attributes"]["type_description"])
            mal = (i, response["data"]["attributes"]["last_analysis_stats"]["malicious"])
            if mal[-1] > 3:
                print('Likely Malicious')
                resultados_hashes.append(mal)
                return((report, resultados_hashes))
            else:
                print("Nothing to see here")
        except:
            print('An error occurred', requests.get(url_hash, headers=headers).status_code)

print(f'-Filetype: {find_hashes(list_hashes)}', f'\n-Flagged by {find_hashes(list_hashes)} vendors')

#print(response.text) # WILL SHOW EVERYTHING VT RESPONDS WITH

""""""""""""""""
que = []
def second_hash(hash):
    for i in hash:
        url_hash = f"https://www.virustotal.com/api/v3/files/{i}"
        response = requests.get(url_hash, headers=headers).json()
        mal = (i, response["data"]["attributes"]["last_analysis_stats"]["malicious"])
        que.append(mal)
    return(que)
print("Hashes:", second_hash(list_hashes))
"""""""""""""""""




