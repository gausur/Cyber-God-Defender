import requests

# ======================== Feodo Tracker (বটনেট C2) ========================
def get_botnet_c2():
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            print(f"✅ Feodo Tracker: {len(data)} C2 servers")
            return data
        else:
            print(f"❌ Feodo HTTP {r.status_code}")
            return []
    except Exception as e:
        print(f"❌ Feodo error: {e}")
        return []

# ======================== OpenPhish (ফিশিং ফিড) ========================
def get_phishing_urls():
    url = "https://openphish.com/feed.txt"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            urls = [line.strip() for line in r.text.splitlines() if line.strip()]
            print(f"✅ OpenPhish: {len(urls)} phishing URLs")
            return urls
        else:
            print(f"❌ OpenPhish HTTP {r.status_code}")
            return []
    except Exception as e:
        print(f"❌ OpenPhish error: {e}")
        return []

# ======================== PhishStats (ফিশিং অ্যানালিটিক্স) ========================
def get_phishstats(limit=10):
    url = f"https://phishstats.info:2096/api/phishing?_sort=-date&_limit={limit}"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            print(f"✅ PhishStats: {len(data)} entries")
            return data
        else:
            print(f"❌ PhishStats HTTP {r.status_code}")
            return []
    except Exception as e:
        print(f"❌ PhishStats error: {e}")
        return []

# ======================== URLhaus CSV ফিড ========================
def get_urlhaus_csv():
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    try:
        r = requests.get(url, timeout=20)
        if r.status_code == 200:
            lines = [l.strip() for l in r.text.splitlines() if l.strip()]
            print(f"✅ URLhaus CSV: {len(lines)} lines")
            return lines
        else:
            print(f"❌ URLhaus HTTP {r.status_code}")
            return []
    except Exception as e:
        print(f"❌ URLhaus error: {e}")
        return []

# ======================== টেস্টিং ========================
if __name__ == "__main__":
    print("Testing Feodo Tracker...")
    c2 = get_botnet_c2()
    if c2:
        for entry in c2[:3]:
            print(f"  IP: {entry.get('ip_address')}, malware: {entry.get('malware')}")
    
    print("\nTesting OpenPhish...")
    phishing_urls = get_phishing_urls()
    if phishing_urls:
        for url in phishing_urls[:3]:
            print(f"  URL: {url}")
    
    print("\nTesting PhishStats...")
    stats = get_phishstats(5)
    if stats:
        for entry in stats[:3]:
            print(f"  URL: {entry.get('url')}, target: {entry.get('target')}")
    
    print("\nTesting URLhaus CSV...")
    csv_data = get_urlhaus_csv()
    if csv_data:
        print(f"  First line: {csv_data[0]}")
