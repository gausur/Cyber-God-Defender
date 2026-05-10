import requests

def get_botnet_c2():
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return r.json()
        return []
    except Exception as e:
        print(f"Feodo error: {e}")
        return []

def get_phishing_urls():
    url = "https://openphish.com/feed.txt"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return [line.strip() for line in r.text.splitlines() if line.strip()]
        return []
    except Exception as e:
        print(f"OpenPhish error: {e}")
        return []

def get_phishstats(limit=10):
    url = f"https://phishstats.info:2096/api/phishing?_sort=-date&_limit={limit}"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return r.json()
        return []
    except Exception as e:
        print(f"PhishStats error: {e}")
        return []

def get_urlhaus_csv():
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    try:
        r = requests.get(url, timeout=20)
        if r.status_code == 200:
            return [l.strip() for l in r.text.splitlines() if l.strip()]
        return []
    except Exception as e:
        print(f"URLhaus error: {e}")
        return []
