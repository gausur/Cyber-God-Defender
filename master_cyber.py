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
import cohere

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

# ======================== GROQ (4 MODEL + FALLBACK) ========================
# অর্ডার: বেস্ট → ফাস্ট → রিজনিং → লাইট
GROQ_MODELS = [
    "llama-3.3-70b-versatile",          # 70B, 128K ctx → বেস্ট কোয়ালিটি
    "openai/gpt-oss-120b",               # 120B, 128K ctx → OpenAI reasoning
    "deepseek-r1-distill-llama-70b",     # 70B, 128K ctx → DeepSeek reasoning
    "llama-3.1-8b-instant",              # 8B, 128K ctx → ফাস্ট ফলব্যাক
]

def ask_groq(text, count=25, label="Groq"):
    key = os.getenv("GROQ_API_KEY")
    if not key:
        print("⚠️ Groq key missing")
        return ""

    client = Groq(api_key=key)
    user_prompt = make_user_prompt(count, text, label)

    for model in GROQ_MODELS:
        for attempt in range(2):  # প্রতি মডেল ২ বার try
            try:
                chat = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": SYSTEM_MESSAGE},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=0.9,
                    max_tokens=8192
                )
                raw = chat.choices[0].message.content
                print(f"✅ Groq ({model}) success, {len(raw)} chars")
                return raw
            except Exception as e:
                err = str(e)
                # HTTP 413 = prompt too large → skip
                if "413" in err:
                    print(f"⚠️ Groq ({model}): 413 payload too large, skip")
                    update_tracker(label, False, err=f"{model}: 413")
                    break  # এই মডেল skip, পরেরটায় যাও
                # Rate limit → অপেক্ষা করে retry
                if "429" in err or "rate" in err.lower():
                    print(f"⏳ Groq ({model}): rate limited, waiting 10s...")
                    time.sleep(10)
                    continue
                print(f"❌ Groq ({model}) error: {err[:100]}")
                update_tracker(label, False, err=f"{model}: {err[:80]}")
                time.sleep(2)
                break  # অন্য error → পরের মডেল
    return ""


# ======================== CEREBRAS ========================
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


# ======================== MISTRAL ========================
def ask_mistral(text, count=25, label="Mistral"):
    key = os.getenv("MISTRAL_API_KEY")
    if not key:
        print("⚠️ Mistral key missing")
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


# ======================== COHERE (MODEL FIX) ========================
COHERE_MODELS = [
    "command-r-08-2024",    # command-r → Cohere-র flagship chat model
    "command-r-plus",        # আরও বড় ভার্সন
    "command",               # লেটেস্ট কমান্ড
]

def ask_cohere(text, count=25, label="Cohere"):
    key = os.getenv("COHERE_API_KEY")
    if not key:
        print("⚠️ Cohere key missing")
        return ""
    co = cohere.Client(key)
    user_prompt = make_user_prompt(count, text, label)
    full_prompt = SYSTEM_MESSAGE + "\n\n" + user_prompt

    for model in COHERE_MODELS:
        try:
            response = co.chat(message=full_prompt, model=model)
            print(f"✅ Cohere ({model}) success")
            return response.text
        except Exception as e:
            err = str(e)
            if "not found" in err.lower() or "404" in err:
                print(f"⚠️ Cohere ({model}) not found, trying next...")
                continue
            print(f"❌ Cohere ({model}) error: {err[:100]}")
            update_tracker(label, False, err=err[:80])
            break  # অন্য error হলে loop থেকে বের হও
    return ""


# ======================== OPENROUTER (FREE MODEL FIX) ========================
# openrouter/free → auto-routing ফ্রি মডেলে
OR_MODELS = [
    "openrouter/free",                       # অটো-বেস্ট ফ্রি
    "google/gemini-2.5-flash-exp:free",      # Gemini Flash free
    "meta-llama/llama-4-maverick:free",      # Llama 4 17B MoE free
    "deepseek/deepseek-r1:free",             # DeepSeek R1 (free tag)
]

def ask_openrouter(model_id, text, count, label):
    key = os.getenv("OPENROUTER_API_KEY")
    if not key:
        print("⚠️ OpenRouter key missing")
        return ""
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    user_prompt = make_user_prompt(count, text, label)

    for model in OR_MODELS:
        data = {
            "model": model,
            "messages": [{"role":"system","content":SYSTEM_MESSAGE},{"role":"user","content":user_prompt}],
            "temperature": 0.9, "max_tokens": 8192
        }
        try:
            r = requests.post("https://openrouter.ai/api/v1/chat/completions",
                            headers=headers, json=data, timeout=90)
            if r.status_code == 200:
                print(f"✅ OpenRouter ({model}) success")
                return r.json()["choices"][0]["message"]["content"]
            elif r.status_code == 402:
                print(f"⚠️ OpenRouter ({model}) 402 Payment Required")
                update_tracker(label, False, err=f"{model}: 402")
                continue
            elif r.status_code == 400:
                print(f"⚠️ OpenRouter ({model}) 400 Bad Request")
                update_tracker(label, False, err=f"{model}: 400")
                continue
            else:
                print(f"❌ OpenRouter ({model}) HTTP {r.status_code}")
                update_tracker(label, False, err=f"{model}: {r.status_code}")
                continue
        except Exception as e:
            print(f"❌ OpenRouter ({model}) exception: {e}")
            update_tracker(label, False, err=str(e)[:80])
            continue
    return ""


# ======================== পার্সার ========================
def parse_qa_text(raw, source="unknown"):
    if not raw:
        return []

    matches = re.findall(
        r'\d*\.?\s*(?:Question|Q):\s*(.*?)\n\s*(?:Answer|A):\s*(.*?)(?=\n\s*\d*\.?\s*(?:Question|Q):|$)',
        raw, re.DOTALL | re.IGNORECASE
    )
    if matches:
        return [{"question":q.strip(), "answer":a.strip(), "source":source} for q, a in matches]

    matches = re.findall(
        r'[*_]*\s*(?:Question|Q)\s*[*_]*\s*:\s*(.*?)\n\s*[*_]*\s*(?:Answer|A)\s*[*_]*\s*:\s*(.*?)(?=\n\s*[*_]*\s*(?:Question|Q)|$)',
        raw, re.DOTALL | re.IGNORECASE
    )
    if matches:
        return [{"question":q.strip(), "answer":a.strip(), "source":source} for q, a in matches]

    lines = raw.split("\n")
    qa = []
    i = 0
    while i < len(lines)-1:
        line_q = lines[i].strip()
        line_a = lines[i+1].strip()
        if (line_q.startswith("Q:") or line_q.startswith("Question:")) and (line_a.startswith("A:") or line_a.startswith("Answer:")):
            q = line_q.split(":",1)[1].strip()
            a = line_a.split(":",1)[1].strip()
            if q and a:
                qa.append({"question":q, "answer":a, "source":source})
            i += 2
        else:
            i += 1
    if qa:
        return qa

    return [{"question": f"Output from {source}", "answer": raw[:500], "source": source}]


def get_output_file():
    return f"dataset_cyber_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.jsonl"


# ======================== মেইন ========================
def main():
    print(f"🚀 Cyber-Defender Non-Stop Run started @ {datetime.now()}")
    end_time = datetime.utcnow() + timedelta(hours=5, minutes=50)
    qa_per_call = 25

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

        # 2. Mistral → SEARCH, Cerebras → DARK, বাকি মিক্সড
        assignments = {
            "Groq":          ("DARK", dark_data),
            "Cerebras":      ("DARK", dark_data),
            "Mistral":       ("SEARCH", search_data),
            "Cohere":        ("DARK", dark_data),
            "OpenRouter":    ("SEARCH", search_data)
        }

        available = {}
        for name, (role, data) in assignments.items():
            key_env = {
                "Groq": "GROQ_API_KEY", "Cerebras": "CEREBRAS_API_KEY",
                "Mistral": "MISTRAL_API_KEY", "Cohere": "COHERE_API_KEY",
                "OpenRouter": "OPENROUTER_API_KEY"
            }.get(name)
            if key_env and not os.getenv(key_env):
                print(f"⚠️ {name}: key missing, skipping")
                continue
            available[name] = (role, data)

        print("📋 Team Assignments:")
        for name, (role, data) in available.items():
            preview = str(data)[:80].replace("\n", " ")
            print(f"  {name} → {role} (Data: {preview}...)")
            update_tracker(name, True, count=0, err=f"Role: {role}")

        # 3. প্যারালাল LLM কল
        all_raws = []
        with ThreadPoolExecutor(max_workers=len(available)) as executor:
            futures = {}
            for name, (role, data) in available.items():
                if name == "Groq":
                    fut = executor.submit(lambda n=name, r=role, d=data: (n, r, ask_groq(d, qa_per_call, n)))
                elif name == "Cerebras":
                    fut = executor.submit(lambda n=name, r=role, d=data: (n, r, ask_cerebras(d, qa_per_call, n)))
                elif name == "Mistral":
                    fut = executor.submit(lambda n=name, r=role, d=data: (n, r, ask_mistral(d, qa_per_call, n)))
                elif name == "Cohere":
                    fut = executor.submit(lambda n=name, r=role, d=data: (n, r, ask_cohere(d, qa_per_call, n)))
                elif name == "OpenRouter":
                    fut = executor.submit(lambda n=name, r=role, d=data: (n, r, ask_openrouter(None, d, qa_per_call, n)))
                futures[fut] = name

            for future in as_completed(futures):
                source_name, role, raw = future.result()
                if raw:
                    all_raws.append((source_name, raw, role))

        # 4. পার্সিং
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
