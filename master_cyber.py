import os, re, json, time
from datetime import datetime, timedelta
from agents.search_team import search_all as search_web
from agents.darkweb_team import (
    get_botnet_c2, get_phishing_urls, get_phishstats,
    get_urlhaus_csv, get_ipinfo, get_otx_pulses
)
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from groq import Groq

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
    "Kubernetes Security, API Security, Supply Chain Attacks"
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
        api_tracker[name] = {"status": "unknown", "last_error": "", "total": 0}
    t = api_tracker[name]
    if ok:
        t["status"] = "working"
        t["last_error"] = ""
        t["total"] += count
    else:
        t["status"] = "failed"
        t["last_error"] = err[:200] if err else "Unknown"

# ---------- Groq ----------
def ask_groq(text, count=25, label="Groq"):
    key = os.getenv("GROQ_API_KEY")
    if not key:
        print("⚠️ Groq key missing")
        return ""
    client = Groq(api_key=key)
    models = ["openai/gpt-oss-120b", "llama-3.1-8b-instant"]
    user_prompt = make_user_prompt(count, text, label)
    for model in models:
        for _ in range(2):
            try:
                chat = client.chat.completions.create(
                    model=model,
                    messages=[{"role":"system","content":SYSTEM_MESSAGE},{"role":"user","content":user_prompt}],
                    temperature=0.9, max_tokens=8192
                )
                print(f"✅ {label} ({model}) success")
                return chat.choices[0].message.content
            except Exception as e:
                err = str(e)
                if "413" not in err:
                    update_tracker(label, False, err=err)
                time.sleep(3)
    return ""

# ---------- Cerebras ----------
def ask_cerebras(text, count=25, label="Cerebras"):
    key = os.getenv("CEREBRAS_API_KEY")
    if not key:
        print("⚠️ Cerebras key missing")
        return ""
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    user_prompt = make_user_prompt(count, text, label)
    data = {
        "model": "llama3.1-8b",
        "messages": [{"role":"system","content":SYSTEM_MESSAGE},{"role":"user","content":user_prompt}],
        "temperature": 0.9, "max_tokens": 8192
    }
    try:
        r = requests.post("https://api.cerebras.ai/v1/chat/completions", headers=headers, json=data, timeout=90)
        if r.status_code == 200:
            print(f"✅ {label} success")
            return r.json()["choices"][0]["message"]["content"]
        else:
            print(f"❌ {label} HTTP {r.status_code}")
            update_tracker(label, False, err=f"HTTP {r.status_code}")
    except Exception as e:
        print(f"❌ {label} exception: {e}")
        update_tracker(label, False, err=str(e))
    return ""

# ---------- Mistral ----------
def ask_mistral(text, count=30, label="Mistral"):
    key = os.getenv("MISTRAL_API_KEY")
    if not key:
        return ""
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    user_prompt = make_user_prompt(count, text, label)
    data = {
        "model": "mistral-small",
        "messages": [{"role":"system","content":SYSTEM_MESSAGE},{"role":"user","content":user_prompt}],
        "temperature": 0.9, "max_tokens": 8192
    }
    try:
        r = requests.post("https://api.mistral.ai/v1/chat/completions", headers=headers, json=data, timeout=90)
        if r.status_code == 200:
            print(f"✅ {label} success")
            return r.json()["choices"][0]["message"]["content"]
        else:
            print(f"❌ {label} HTTP {r.status_code}")
            update_tracker(label, False, err=f"HTTP {r.status_code}")
    except Exception as e:
        print(f"❌ {label} exception: {e}")
        update_tracker(label, False, err=str(e))
    return ""

# ---------- OpenRouter (শুধু DeepSeek-R1) ----------
def ask_openrouter(model_id, text, count, label):
    key = os.getenv("OPENROUTER_API_KEY")
    if not key:
        return ""
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    user_prompt = make_user_prompt(count, text, label)
    data = {
        "model": model_id,
        "messages": [{"role":"system","content":SYSTEM_MESSAGE},{"role":"user","content":user_prompt}],
        "temperature": 0.9, "max_tokens": 8192
    }
    try:
        r = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=data, timeout=90)
        if r.status_code == 200:
            return r.json()["choices"][0]["message"]["content"]
        else:
            print(f"❌ {label} HTTP {r.status_code}")
            update_tracker(label, False, err=f"HTTP {r.status_code}")
    except Exception as e:
        print(f"❌ {label} exception: {e}")
        update_tracker(label, False, err=str(e))
    return ""

# ---------- পার্সার ----------
def parse_qa_text(raw, source="unknown"):
    if not raw: return []
    matches = re.findall(
        r'\d*\.?\s*(?:Question|Q):\s*(.*?)\n\s*(?:Answer|A):\s*(.*?)(?=\n\s*\d*\.?\s*(?:Question|Q):|$)',
        raw, re.DOTALL | re.IGNORECASE
    )
    qa = [{"question":q.strip(), "answer":a.strip(), "source":source} for q, a in matches]
    if qa: return qa
    matches2 = re.findall(
        r'\*?\*?(?:Question|Q)\*?\*?:\s*(.*?)\n\s*\*?\*?(?:Answer|A)\*?\*?:\s*(.*?)(?=\n\s*\*?\*?(?:Question|Q)|$)',
        raw, re.DOTALL | re.IGNORECASE
    )
    return [{"question":q.strip(), "answer":a.strip(), "source":source} for q, a in matches2]

def get_output_file():
    return f"dataset_cyber_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.jsonl"

# ---------- মেইন ----------
def main():
    print(f"🚀 Cyber-Defender Non-Stop Run started @ {datetime.now()}")
    end_time = datetime.utcnow() + timedelta(hours=5, minutes=50)
    qa_per_call = 25

    # শুধু কাজ করা মডেল
    working_llms = ["Groq", "Cerebras", "Mistral", "DeepSeek-R1"]
    or_model_id = "deepseek/deepseek-r1"
    cycle_counter = 0

    while datetime.utcnow() < end_time:
        cycle_counter += 1
        start_cycle = time.time()

        # 1. ডেটা সংগ্রহ
        dark_data = ""
        dark_data += "\n=== Feodo C2 ===\n" + str(get_botnet_c2())
        dark_data += "\n=== URLhaus CSV ===\n" + "\n".join(get_urlhaus_csv()[:10])
        dark_data += "\n=== Phishing Feed ===\n" + "\n".join(get_phishing_urls()[:10])
        dark_data += "\n=== IPinfo ===\n" + str(get_ipinfo("8.8.8.8"))
        dark_data += "\n=== OTX Pulses ===\n" + str(get_otx_pulses())

        search_data = search_web()

        print(f"📊 Cycle {cycle_counter}: Dark {len(dark_data)} chars, Search {len(search_data)} chars")

        # 2. টিম ভাগ (সহজ ও নির্ভরযোগ্য)
        assignments = {
            "Groq": ("DARK", dark_data),
            "Cerebras": ("DARK", dark_data),
            "Mistral": ("DARK", dark_data),
            "DeepSeek-R1": ("SEARCH", search_data)
        }

        print("📋 Team Assignments:")
        for name, (role, data) in assignments.items():
            preview = str(data)[:80].replace("\n", " ")
            print(f"  {name} → {role} (Data: {preview}...)")
            update_tracker(name, True, count=0, err=f"Role: {role}")

        # 3. প্যারালাল LLM কল
        all_raws = []
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {}

            # Groq
            futures[executor.submit(
                lambda: ("Groq", assignments["Groq"][0], ask_groq(assignments["Groq"][1], qa_per_call, "Groq"))
            )] = "Groq"

            # Cerebras
            futures[executor.submit(
                lambda: ("Cerebras", assignments["Cerebras"][0], ask_cerebras(assignments["Cerebras"][1], qa_per_call, "Cerebras"))
            )] = "Cerebras"

            # Mistral
            futures[executor.submit(
                lambda: ("Mistral", assignments["Mistral"][0], ask_mistral(assignments["Mistral"][1], qa_per_call, "Mistral"))
            )] = "Mistral"

            # DeepSeek-R1
            role_deepseek, data_deepseek = assignments["DeepSeek-R1"]
            futures[executor.submit(
                lambda: ("DeepSeek-R1", role_deepseek, ask_openrouter(or_model_id, data_deepseek, qa_per_call, "DeepSeek-R1"))
            )] = "DeepSeek-R1"

            for future in as_completed(futures):
                source_name, role, raw = future.result()
                if raw:
                    all_raws.append((source_name, raw, role))

        # 4. পার্সিং ও এন্ট্রি গণনা
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
                print(f"  ✅ {api_name}: working (total: {info['total']})")
            else:
                print(f"  ❌ {api_name}: failed - {info['last_error']}")

        # 5. ফাইল ও পুশ
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

        elapsed = time.time() - start_cycle
        sleep_time = max(5, 10 - elapsed)
        print(f"⏳ Sleeping {sleep_time:.1f}s...")
        time.sleep(sleep_time)

    print("🏁 Non-stop run completed.")

if __name__ == "__main__":
    main()
