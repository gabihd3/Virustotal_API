import requests
import base64


class VirusTotalAPI:
    """This is a 
    VirusTotalAPI class"""

    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {
        "Accept": "application/json",
        "X-Apikey": api_key
        }
        
    def _check_malicious(self, endpoint, item):
        url = f"https://www.virustotal.com/api/v3/{endpoint}/{item}"
        response = requests.get(url, headers=self.headers)
        if response.status_code // 100 != 2:
            raise Exception(f"Error: request to {url} failed with status code {response.status_code}")

        try:
            data = response.json()
        except ValueError:
            raise Exception(f"Error: response from {url} was not valid JSON")

        if "error" in data:
            raise Exception(f"Error: {data['error']['message']}")
        malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        return malicious

    def find(self, items, endpoint):
        results = []
        for item in items:
            report = (item, self._check_malicious(endpoint, item))
            if report[-1] > 0:
                results.append(report)
        return results

    def find_ips(self, ips):
        return self.find(ips, "ip_addresses")

    def find_hashes(self, hashes):
        return self.find(hashes, "files")
    
    def find_domains(self, domains):
        return self.find(domains, "domains")

    def find_urls(self, urls):
        encoded = []
        test = {}
        for url in urls: # ENCODE EACH URL
            url_id = base64.urlsafe_b64encode(f"{url}".encode()).decode().strip("=")
            encoded.append(url_id)
            test[url] = url_id
        results = []
        for item in encoded: # PASS THE ENCODED VERSIONS THRU VT
            report = (item, self._check_malicious("urls", item))
            if report[-1] > 0:
                results.append(report)
        final = [] # IF THERE ARE ANY HITS, PRINT THE ORIGINAL URL INSTEAD OF THE ENCODED VERSION
        for key, value in test.items():
            for result in results:
                if value in result[0]:
                    final.append((key, result[-1]))
        return final
    """
    def test_find_urls(self, urls):
        encoded = []
        test = {}
        for url in urls: # ENCODE EACH URL
            url_id = base64.urlsafe_b64encode(f"{url}".encode()).decode().strip("=")
            encoded.append(url_id)
            test[url] = url_id
        results = [(item, self._check_malicious("urls", item)) for item in encoded if (item, self._check_malicious("urls", item))[-1] > 0]
        final = [(key, result[-1]) for key, value in test.items() for result in results if value in result[0]]
        return final
    """

help(VirusTotalAPI) 

list_ips = ["195.54.160.149", "165.227.239.108", "167.71.13.196", "84.70.180.143", "98.0.242.10"]
list_hashes = ["ef8b5595808021dff2f1013a0b06275945021a7e871e6776c48523e950e01d4f", "9841973ca2ea111ec8378ba3ac08d4056ac9bdbae3f50b14de1872b7a6419b2c"]
list_domains = ["bbc.com", "nestleservers.xyz", "linkedin.com"]
list_urls = ["https://www.linkedin.com", "https://ywodli69.top", "https://ywobeb710.top/"]

vt = VirusTotalAPI('INSERT API HERE')

print(vt.find_ips(list_ips))
print(vt.find_hashes(list_hashes))
print(vt.find_domains(list_domains))
print(vt.find_urls(list_urls))


