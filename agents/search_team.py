import os
import requests
from ddgs import DDGS
from serpapi import GoogleSearch
from gdeltdoc import GdeltDoc, Filters

# ======================== ওয়েব সার্চ API ========================

def search_duckduckgo():
    """DuckDuckGo দিয়ে সাইবার সিকিউরিটি সার্চ (কোনো Key লাগে না)"""
    results = []
    queries = [
        "latest cyber attack news 2025",
        "CVE exploit PoC ransomware",
        "cyber threat intelligence report"
    ]
    try:
        ddgs = DDGS()
        for q in queries:
            res = ddgs.text(q, max_results=5)
            results.append(str(res))
        print(f"✅ DuckDuckGo: {len(results)} queries done")
    except Exception as e:
        print(f"❌ DuckDuckGo error: {e}")
    return "\n\n".join(results)

def search_serpapi():
    """SerpAPI (Google) দিয়ে সাইবার সার্চ (SerpAPI Key লাগবে)"""
    key = os.getenv("SERPAPI_KEY")
    if not key:
        return ""
    try:
        serp = GoogleSearch({
            "q": "cyber attack today CVE exploit",
            "api_key": key
        })
        out = serp.get_dict()
        print("✅ SerpAPI success")
        return str(out.get("organic_results", []))
    except Exception as e:
        print(f"❌ SerpAPI error: {e}")
        return ""

def search_gdelt():
    """GDELT দিয়ে সাইবার নিউজ সার্চ (কোনো Key লাগে না)"""
    try:
        gd = GdeltDoc()
        f = Filters(
            keyword="cyber attack",
            start_date="2026-05-01",
            end_date="2026-05-09"
        )
        articles = gd.article_search(f)
        print("✅ GDELT success")
        return str(articles.head(5).to_dict())
    except Exception as e:
        print(f"❌ GDELT error: {e}")
        return ""

def search_openalex():
    """OpenAlex দিয়ে সাইবার রিসার্চ পেপার সার্চ (কোনো Key লাগে না)"""
    try:
        oa = requests.get(
            "https://api.openalex.org/works",
            params={"search": "cybersecurity attack", "per_page": 5}
        ).json()
        print("✅ OpenAlex success")
        return str(oa)
    except Exception as e:
        print(f"❌ OpenAlex error: {e}")
        return ""

def search_semantic_scholar():
    """Semantic Scholar দিয়ে একাডেমিক পেপার সার্চ (কোনো Key লাগে না)"""
    try:
        ss = requests.get(
            "https://api.semanticscholar.org/graph/v1/paper/search",
            params={"query": "cyber threat intelligence", "limit": 5}
        ).json()
        print("✅ Semantic Scholar success")
        return str(ss)
    except Exception as e:
        print(f"❌ Semantic Scholar error: {e}")
        return ""

# ======================== থ্রেট ইন্টেল API (No-Key) ========================

def fetch_feodo_tracker():
    """Feodo Tracker: বটনেট C2 সার্ভার ট্র্যাক (কোনো Key লাগে না)"""
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            print(f"✅ Feodo Tracker: {len(data)} C2 servers")
            return str(data)
        else:
            print(f"❌ Feodo HTTP {r.status_code}")
            return ""
    except Exception as e:
        print(f"❌ Feodo error: {e}")
        return ""

def fetch_urlhaus(limit=10):
    """URLhaus: ম্যালওয়্যার URL ফিড (কোনো Key লাগে না)"""
    url = f"https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            print(f"✅ URLhaus: {len(data.get('urls', []))} malware URLs")
            return str(data)
        else:
            print(f"❌ URLhaus HTTP {r.status_code}")
            return ""
    except Exception as e:
        print(f"❌ URLhaus error: {e}")
        return ""

def fetch_openphish():
    """OpenPhish: ফিশিং URL ফিড (কোনো Key লাগে না)"""
    url = "https://openphish.com/feed.txt"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            urls = [line.strip() for line in r.text.splitlines() if line.strip()]
            print(f"✅ OpenPhish: {len(urls)} phishing URLs")
            return "\n".join(urls)
        else:
            print(f"❌ OpenPhish HTTP {r.status_code}")
            return ""
    except Exception as e:
        print(f"❌ OpenPhish error: {e}")
        return ""

def fetch_phishstats(limit=10):
    """PhishStats: ফিশিং অ্যানালিটিক্স (কোনো Key লাগে না)"""
    url = f"https://phishstats.info:2096/api/phishing?_sort=-date&_limit={limit}"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            print(f"✅ PhishStats: {len(data)} entries")
            return str(data)
        else:
            print(f"❌ PhishStats HTTP {r.status_code}")
            return ""
    except Exception as e:
        print(f"❌ PhishStats error: {e}")
        return ""

# ======================== সব ডেটা একসাথে আনো ========================

def search_all():
    """সব সার্চ ও থ্রেট ইন্টেল API থেকে ডেটা একত্রিত করবে"""
    results = []
    
    # ওয়েব সার্চ
    results.append("=== DuckDuckGo ===\n" + search_duckduckgo())
    results.append("=== GDELT ===\n" + search_gdelt())
    results.append("=== OpenAlex ===\n" + search_openalex())
    results.append("=== Semantic Scholar ===\n" + search_semantic_scholar())
    results.append("=== SerpAPI ===\n" + search_serpapi())
    
    # থ্রেট ইন্টেল (No-Key)
    results.append("=== Feodo Tracker (Botnet C2) ===\n" + fetch_feodo_tracker())
    results.append("=== URLhaus (Malware URLs) ===\n" + fetch_urlhaus())
    results.append("=== OpenPhish (Phishing Feed) ===\n" + fetch_openphish())
    results.append("=== PhishStats ===\n" + fetch_phishstats())
    
    return "\n\n".join(results)

if __name__ == "__main__":
    data = search_all()
    print(f"\n📊 Total data length: {len(data)} characters")
