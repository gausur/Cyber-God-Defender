import requests

def check_vulnerability(cve_id):
    url = f"https://api.contrastapi.com/vulns/cve/{cve_id}"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return r.json()
        else:
            return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_ip_reputation(ip_address):
    url = f"https://api.contrastapi.com/reputation/ip/{ip_address}"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return r.json()
        else:
            return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    print("Testing CVE-2024-1234...")
    print(check_vulnerability("CVE-2024-1234"))
    print("\nTesting IP 8.8.8.8...")
    print(check_ip_reputation("8.8.8.8"))
