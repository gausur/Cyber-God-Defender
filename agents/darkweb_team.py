import os, requests

# ======================== No-Key APIs ========================

def get_botnet_c2():
    """Feodo Tracker: বটনেট C2 (কোনো Key লাগে না)"""
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            print(f"✅ Feodo Tracker: {len(data)} C2 servers")
            return data[:10]  # শীর্ষ ১০
        return []
    except Exception as e:
        print(f"❌ Feodo error: {e}")
        return []

def get_phishing_urls():
    """OpenPhish: ফিশিং URL (কোনো Key লাগে না)"""
    url = "https://openphish.com/feed.txt"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            urls = [line.strip() for line in r.text.splitlines() if line.strip()]
            print(f"✅ OpenPhish: {len(urls)} phishing URLs")
            return urls[:20]
        return []
    except Exception as e:
        print(f"❌ OpenPhish error: {e}")
        return []

def get_phishstats(limit=10):
    """PhishStats: ফিশিং অ্যানালিটিক্স (কোনো Key লাগে না)"""
    url = f"https://phishstats.info:2096/api/phishing?_sort=-date&_limit={limit}"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            print(f"✅ PhishStats: {len(data)} entries")
            return data
        return []
    except Exception as e:
        print(f"❌ PhishStats error: {e}")
        return []

def get_urlhaus_csv():
    """URLhaus: ম্যালওয়্যার URL CSV (কোনো Key লাগে না)"""
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    try:
        r = requests.get(url, timeout=20)
        if r.status_code == 200:
            lines = [l.strip() for l in r.text.splitlines() if l.strip()]
            print(f"✅ URLhaus CSV: {len(lines)} lines")
            return lines[:15]
        return []
    except Exception as e:
        print(f"❌ URLhaus error: {e}")
        return []

def get_malwarebazaar(limit=10):
    """MalwareBazaar: ম্যালওয়্যার স্যাম্পল (কোনো Key লাগে না)"""
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_recent", "selector": "time", "limit": limit}
    try:
        r = requests.post(url, data=data, timeout=15)
        if r.status_code == 200:
            result = r.json()
            samples = result.get("data", [])
            print(f"✅ MalwareBazaar: {len(samples)} recent samples")
            return [{"sha256_hash": s.get("sha256_hash"), "file_name": s.get("file_name", ""), "signature": s.get("signature", "")} for s in samples]
        return []
    except Exception as e:
        print(f"❌ MalwareBazaar error: {e}")
        return []

def get_threatfox_iocs(query="", limit=10):
    """ThreatFox: IOC খোঁজ (কোনো Key লাগে না)"""
    url = "https://threatfox-api.abuse.ch/api/v1/"
    data = {"query": "search_ioc", "search_term": query if query else "malware", "limit": limit}
    try:
        r = requests.post(url, json=data, timeout=15)
        if r.status_code == 200:
            result = r.json()
            iocs = result.get("data", [])
            print(f"✅ ThreatFox: {len(iocs)} IOCs")
            return iocs
        return []
    except Exception as e:
        print(f"❌ ThreatFox error: {e}")
        return []

# ======================== ContrastAPI (No Key) ========================

def contrastapi_cve(cve_id="CVE-2024-1234"):
    """ContrastAPI: CVE লুকআপ (কোনো Key লাগে না, ১০০ ক্রেডিট/ঘণ্টা)"""
    url = f"https://api.contrastcyber.com/v1/cve/{cve_id}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return r.json()
        return {}
    except Exception as e:
        print(f"❌ ContrastAPI CVE error: {e}")
        return {}

def contrastapi_ip(ip):
    """ContrastAPI: IP রেপুটেশন (AbuseIPDB + Shodan)"""
    url = f"https://api.contrastcyber.com/v1/ip/{ip}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return r.json()
        return {}
    except Exception as e:
        print(f"❌ ContrastAPI IP error: {e}")
        return {}

def contrastapi_domain(domain):
    """ContrastAPI: ডোমেইন রিকন + SSL + DNS"""
    url = f"https://api.contrastcyber.com/v1/domain/{domain}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return r.json()
        return {}
    except Exception as e:
        print(f"❌ ContrastAPI Domain error: {e}")
        return {}

# ======================== API with Key ========================

def get_ipinfo(ip="8.8.8.8"):
    """IPinfo Lite: আনলিমিটেড IP জিওলোকেশন"""
    token = os.getenv("IPINFOLITE_API_KEY")
    if not token:
        return {}
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(f"https://api.ipinfo.io/lite/{ip}", headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json()
        return {}
    except Exception as e:
        print(f"❌ IPinfo error: {e}")
        return {}

def get_otx_pulses():
    """AlienVault OTX: সাবস্ক্রাইবড Pulses (আনলিমিটেড)"""
    key = os.getenv("ALIENVAULT_API_KEY")
    if not key:
        return []
    headers = {"X-OTX-API-KEY": key}
    try:
        r = requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed?page=1", headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            pulses = data.get("results", [])
            print(f"✅ OTX: {len(pulses)} subscribed pulses")
            # শুধু গুরুত্বপূর্ণ তথ্য নেব
            summary = []
            for p in pulses[:10]:
                summary.append({
                    "name": p.get("name", ""),
                    "description": p.get("description", "")[:200],
                    "created": p.get("created", ""),
                    "tags": p.get("tags", []),
                    "indicator_count": p.get("indicator_count", 0)
                })
            return summary
        return []
    except Exception as e:
        print(f"❌ OTX error: {e}")
        return []
