import os, re, json, time
from datetime import datetime, timedelta
from agents.search_team import search_all as search_web
from agents.darkweb_team import (
    get_botnet_c2,
    get_malware_urls,
    get_phishing_urls,
    get_phishstats
)
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# ======================== SYSTEM MESSAGE ========================
SYSTEM_MESSAGE = (
    "You are an elite Red Team operator and PhD‑level cybersecurity researcher. "
    "Generate question‑answer pairs that are extremely detailed, technical, "
    "and explanatory (150‑300 words each). "
    "Answers MUST include: (1) technical mechanisms or attack vectors, "
    "(2) specific CVEs, tools, or commands, (3) mitigation strategies, "
    "(4) real‑world examples or threat actor campaigns. "
    "Answers must NEVER be one‑liners or vague. "
    "Questions must be deep, analytical, and varied – rotate between: "
    "How to exploit, How to defend, Analyze the CVE, Compare tools, "
    "Discuss the threat actor, Incident response steps, Forensic analysis. "
    "Every question‑answer pair MUST be UNIQUE."
)

TOPICS = (
    "Penetration Testing, Exploit Development, Malware Analysis, "
    "Network Security, Incident Response, Digital Forensics, "
    "Threat Intelligence, Vulnerability Research, "
    "Web Application Security, Cloud Security, Active Directory Attacks, "
    "Privilege Escalation, Phishing & Social Engineering, Reverse Engineering, "
    "Cryptography, Wireless Security, IoT Security, SCADA/ICS Security, "
    "Red Teaming, Blue Teaming, Purple Teaming, MITRE ATT&CK, "
    "Zero‑Day Research, Bug Bounty, OSINT, C2 Frameworks, "
    "Data Exfiltration, Lateral Movement, Persistence Mechanisms, "
    "Evasion Techniques, Firewall & IDS/IPS Evasion, "
    "Kubernetes Security, API Security, Supply Chain Attacks,Stuxnet, WannaCry, NotPetya, DarkHotel, Zero-Click Exploit, Remote Code Execution (RCE), Spear Phishing, Evil Twin Attack, BGP Hijacking, DNS Cache Poisoning, SQL Injection, Ransomware-as-a-Service (RaaS), APT (Advanced Persistent Threat), SolarWinds Hack, Heartbleed, BlueKeep, GhostNet, Sandworm,"
)

def make_user_prompt(count, text, source_label):
    return (
        f"Generate exactly {count} unique cybersecurity Q&A pairs using the provided {source_label} data. "
        f"Topics: {TOPICS}. Rotate topics.\n"
        f"Format:\nQuestion: ...\nAnswer: ...\n\n"
        f"Text: {str(text)[:2500]}"
    )

# ======================== API ট্র্যাকিং ========================
api_tracker = {}

def update_tracker(name, ok, count=0, err=""):
    if name not in api_tracker:
        api_tracker[name] = {"status": "unknown", "last_error": "", "total": 0, "roles": []}
    t = api_tracker[name]
    if ok:
        t["status"] = "working"
        t["last_error"] = ""
        t["total"] += count
    else:
        t["status"] = "failed"
        t["last_error"] = err[:200] if err else "Unknown"

# ---------- Venice Uncensored (OpenRouter) ----------
def ask_venice(text, count=25, source_label="Unknown"):
    key = os.getenv("OPENROUTER_API_KEY")
    if not key:
        print("⚠️ OpenRouter key missing")
        return ""
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json"
    }
    user_prompt = make_user_prompt(count, text, source_label)
    data = {
        "model": "venice/venice-dolphin-mistral-24b",
        "messages": [
            {"role": "system", "content": SYSTEM_MESSAGE},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.9,
        "max_tokens": 8192
    }
    try:
        r = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers, json=data, timeout=90
        )
        if r.status_code == 200:
            return r.json()["choices"][0]["message"]["content"]
        else:
            print(f"❌ Venice HTTP {r.status_code}: {r.text[:150]}")
            update_tracker("Venice", False, err=f"HTTP {r.status_code}")
    except Exception as e:
        print(f"❌ Venice exception: {e}")
        update_tracker("Venice", False, err=str(e))
    return ""

# ---------- Featherless (Oracle.Aritha-AI) ----------
def ask_featherless(text, count=25, source_label="Unknown"):
    key = os.getenv("FEATHERLESS_API_KEY")
    if not key:
        print("⚠️ Featherless key missing")
        return ""
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json"
    }
    user_prompt = make_user_prompt(count, text, source_label)
    data = {
        "model": "Oracle.Aritha-AI",
        "messages": [
            {"role": "system", "content": SYSTEM_MESSAGE},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.9,
        "max_tokens": 8096
    }
    try:
        r = requests.post(
            "https://api.featherless.ai/v1/chat/completions",
            headers=headers, json=data, timeout=90
        )
        if r.status_code == 200:
            return r.json()["choices"][0]["message"]["content"]
        else:
            print(f"❌ Featherless HTTP {r.status_code}: {r.text[:150]}")
            update_tracker("Featherless", False, err=f"HTTP {r.status_code}")
    except Exception as e:
        print(f"❌ Featherless exception: {e}")
        update_tracker("Featherless", False, err=str(e))
    return ""

# ---------- Sherlock Models (LLM Gateway) ----------
def ask_sherlock(text, count=25, source_label="Unknown"):
    key = os.getenv("SHERLOCK_MODELS_API")
    if not key:
        print("⚠️ Sherlock key missing")
        return ""
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json"
    }
    user_prompt = make_user_prompt(count, text, source_label)
    data = {
        "model": "sherlock-alpha-stealth-v2",
        "messages": [
            {"role": "system", "content": SYSTEM_MESSAGE},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.9,
        "max_tokens": 8000
    }
    try:
        r = requests.post(
            "https://api.llmgateway.io/v1/chat/completions",
            headers=headers, json=data, timeout=90
        )
        if r.status_code == 200:
            return r.json()["choices"][0]["message"]["content"]
        else:
            print(f"❌ Sherlock HTTP {r.status_code}: {r.text[:150]}")
            update_tracker("Sherlock", False, err=f"HTTP {r.status_code}")
    except Exception as e:
        print(f"❌ Sherlock exception: {e}")
        update_tracker("Sherlock", False, err=str(e))
    return ""

# ---------- পার্সার ----------
def parse_qa_text(raw, source="unknown"):
    if not raw: return []
    matches = re.findall(
        r'\d*\.?\s*(?:Question|Q):\s*(.*?)\n\s*(?:Answer|A):\s*(.*?)'
        r'(?=\n\s*\d*\.?\s*(?:Question|Q):|$)',
        raw, re.DOTALL | re.IGNORECASE
    )
    qa = [{"question": q.strip(), "answer": a.strip(), "source": source} for q, a in matches]
    if qa: return qa
    matches2 = re.findall(
        r'\*?\*?(?:Question|Q)\*?\*?:\s*(.*?)\n\s*\*?\*?(?:Answer|A)\*?\*?:\s*(.*?)'
        r'(?=\n\s*\*?\*?(?:Question|Q)|$)',
        raw, re.DOTALL | re.IGNORECASE
    )
    return [{"question": q.strip(), "answer": a.strip(), "source": source} for q, a in matches2]

def get_output_file():
    return f"dataset_cyber_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.jsonl"

# ---------- মেইন ----------
def main():
    print(f"🚀 Cyber-Defender Non-Stop Run started @ {datetime.now()}")
    end_time = datetime.utcnow() + timedelta(hours=5, minutes=50)
    qa_per_call = 15  # রেট লিমিটের জন্য কিউএ সংখ্যা কমালাম

    # টিম মেম্বার
    llm_team = ["Venice", "Featherless", "Sherlock"]
    cycle_counter = 0

    while datetime.utcnow() < end_time:
        cycle_counter += 1
        start_cycle = time.time()

        # 1. ডার্ক ও সার্চ ডেটা সংগ্রহ
        dark_data = ""
        dark_data += "\n=== Feodo Botnet C2 ===\n" + str(get_botnet_c2())
        dark_data += "\n=== Malware URLs (Recent) ===\n" + str(get_malware_urls(5))
        dark_data += "\n=== Phishing Feed ===\n" + "\n".join(get_phishing_urls()[:10])

        search_data = search_web()  # DuckDuckGo, GDELT, ইত্যাদি থেকে ডেটা

        print(f"📊 Cycle {cycle_counter}: Dark data {len(dark_data)} chars, Search data {len(search_data)} chars")

        # 2. ডায়নামিক রোল অ্যাসাইনমেন্ট (পালা পদ্ধতি)
        if cycle_counter % 2 == 1:  # বিজোড় সাইকেল
            assignments = {
                "Venice": ("DARK", dark_data),
                "Featherless": ("SEARCH", search_data),
                "Sherlock": ("DARK", dark_data)
            }
        else:  # জোড় সাইকেল (রোল রিভার্সড)
            assignments = {
                "Venice": ("SEARCH", search_data),
                "Featherless": ("DARK", dark_data),
                "Sherlock": ("SEARCH", search_data)
            }

        # ভিজুয়াল অ্যাসাইনমেন্ট প্রিন্ট
        print("📋 Team Assignments for this Cycle:")
        for llm_name in llm_team:
            role, data = assignments[llm_name]
            preview = str(data)[:80].replace("\n", " ")
            print(f"  {llm_name} → {role} (Data: {preview}...)")
            update_tracker(llm_name, True, count=0, err=f"Role: {role}")

        # 3. প্যারালাল LLM কল
        all_raws = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(
                    lambda name="Venice", role="DARK", data=dark_data: (
                        "Venice", role, ask_venice(data, qa_per_call, f"DARK Intel")
                    )
                ): "Venice",
                executor.submit(
                    lambda name="Featherless", role="SEARCH", data=search_data: (
                        "Featherless", role, ask_featherless(data, qa_per_call, f"SEARCH Intel")
                    )
                ): "Featherless",
                executor.submit(
                    lambda name="Sherlock", role="DARK" if cycle_counter % 2 == 1 else "SEARCH",
                    data=dark_data if cycle_counter % 2 == 1 else search_data: (
                        "Sherlock", role, ask_sherlock(data, qa_per_call, f"{role} Intel")
                    )
                ): "Sherlock"
            }

            for future in as_completed(futures):
                future_name = futures[future]
                source_name, role, raw = future.result()
                if raw:
                    all_raws.append((source_name, raw, role))

        # 4. পার্সিং ও সোর্স গণনা
        entries = []
        entries_per_source = {}
        for source_name, raw, role in all_raws:
            parsed = parse_qa_text(raw, source=f"{source_name} ({role})")
            entries.extend(parsed)
            key = f"{source_name} ({role})"
            entries_per_source[key] = entries_per_source.get(key, 0) + len(parsed)
            update_tracker(source_name, True, count=len(parsed))

        print(f"📝 Total entries: {len(entries)}")
        print(f"📊 Sources: {entries_per_source}")
        print("📋 API Status Report:")
        for api_name, info in api_tracker.items():
            if info["status"] == "working":
                sources_list = ", ".join(set([e["source"] for e in entries if api_name in e["source"]])) or "N/A"
                print(f"  ✅ {api_name}: working (total entries: {info['total']})")
            else:
                print(f"  ❌ {api_name}: failed - {info['last_error']}")

        # 5. ফাইল লেখা ও পুশ
        if entries:
            out_file = get_output_file()
            with open(out_file, "w", encoding="utf-8") as f:
                for e in entries:
                    f.write(json.dumps(e, ensure_ascii=False) + "\n")

            token = os.environ.get("GH_TOKEN")
            repo = os.environ["REPOSITORY"]
            remote_url = f"https://x-access-token:{token}@github.com/{repo}.git"

            os.system("git config user.name 'Cyber-God-Bot'")
            os.system("git config user.email 'bot@cyber-defender.ai'")
            os.system(f"git add {out_file}")
            ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
            os.system(f"git commit -m 'Cyber dataset {ts}' || echo 'No changes'")
            os.system(f"git remote set-url origin {remote_url}")
            os.system("git push")
            print(f"✅ {len(entries)} entries pushed in {out_file}")
        else:
            print("⚠️ No entries this cycle.")

        # 6. বিরতি
        elapsed = time.time() - start_cycle
        sleep_time = max(15, 30 - elapsed)
        print(f"⏳ Sleeping {sleep_time:.1f}s...")
        time.sleep(sleep_time)

    print("🏁 Non-stop run completed.")

if __name__ == "__main__":
    main()
