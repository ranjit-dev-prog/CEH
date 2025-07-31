import requests
import argparse
import random
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, init

init(autoreset=True)

# ✅ API wordlists
API_WORDLISTS = ["https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"]

# 🔐 Risky keywords
RISKY_KEYWORDS = ["admin", "login", "panel", "config", "phpmyadmin", "cpanel", "shell", "upload", "dashboard", "backup"]

# 📊 Summary
SUMMARY = {"200": 0, "403": 0, "301": 0, "302": 0}
FOUND = []
RISKY = []

EXTENSIONS = ["", ".php", ".html", ".bak", ".zip", "/"]
UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
]

# 📦 Fetch wordlists from API
def fetch_wordlist():
    words = set()
    for url in API_WORDLISTS:
        try:
            print(Fore.YELLOW + f"[*] Fetching: {url}")
            res = requests.get(url, timeout=10)
            res.raise_for_status()
            words.update(line.strip() for line in res.text.splitlines() if line.strip())
        except Exception as e:
            print(Fore.RED + f"[!] Failed to fetch {url} - {e}")
    return list(words)

# 🔍 Extract paths from .js files
def extract_paths_from_js(js_code):
    return re.findall(r'\/[a-zA-Z0-9\/\-_\.]+', js_code)

# 🚨 Risk check
def is_risky(path):
    return any(risk in path.lower() for risk in RISKY_KEYWORDS)

# 🔬 Main scanner
def scan_path(base_url, path):
    results = []
    for ext in EXTENSIONS:
        full_url = urljoin(base_url.rstrip("/") + "/", path + ext)
        headers = {'User-Agent': random.choice(UA_LIST)}
        try:
            res = requests.get(full_url, headers=headers, timeout=4, allow_redirects=False)
            code = res.status_code
            if code in [200, 301, 302, 403]:
                color = {
                    200: Fore.GREEN,
                    301: Fore.CYAN,
                    302: Fore.CYAN,
                    403: Fore.YELLOW
                }.get(code, Fore.RESET)

                line = f"[{code}] {full_url}"
                print(color + line)

                FOUND.append(line)
                SUMMARY[str(code)] += 1

                if is_risky(full_url):
                    RISKY.append(full_url)

                if code == 200 and full_url.endswith(".js"):
                    js_paths = extract_paths_from_js(res.text)
                    for js_path in js_paths:
                        print(Fore.BLUE + f"[JS] {js_path}")
        except requests.RequestException:
            pass

    return results

# 🎯 Main Function
def main():
    parser = argparse.ArgumentParser(description="DirVader-Ultimate v4.0 – Gobuster-Mode (🔥 Advanced, API + Fast + Smart)")
    parser.add_argument("url", help="Target URL (e.g., http://example.com)")
    args = parser.parse_args()

    target_url = args.url.strip()

    print(Fore.CYAN + f"\n🚀 Target: {target_url}")
    print(Fore.YELLOW + "📦 Fetching API Wordlists...")
    wordlist = fetch_wordlist()
    print(Fore.GREEN + f"[+] Total Words: {len(wordlist)}")

    print(Fore.MAGENTA + "\n🔍 Starting scan...\n" + "-"*60)

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_path, target_url, word): word for word in wordlist}
        for future in as_completed(futures):
            future.result()

    # 🧾 Final Summary
    print(Fore.MAGENTA + "\n" + "="*60)
    print(Fore.CYAN + "📊 DirVader Summary:")
    print(Fore.GREEN + f"✅ 200 OK: {SUMMARY['200']}")
    print(Fore.YELLOW + f"🚫 403 Forbidden: {SUMMARY['403']}")
    print(Fore.CYAN + f"🔁 301 Redirect: {SUMMARY['301']}")
    print(Fore.CYAN + f"🔁 302 Redirect: {SUMMARY['302']}")
    print(Fore.RED + f"⚠️  Risky Panels Detected: {len(RISKY)}")
    for panel in RISKY:
        print(Fore.RED + f" - {panel}")
    print(Fore.MAGENTA + "="*60)

if __name__ == "__main__":
    main()
