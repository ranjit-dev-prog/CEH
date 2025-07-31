# DirVader-Ultimate v3.2 – Fast, Terminal-Only Mode

import requests
import os
import random
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, init
from tqdm import tqdm

init(autoreset=True)

FOUND = []
SUMMARY = {"200": 0, "403": 0, "301": 0, "302": 0}
UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
]

API_WORDLISTS = [
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"]

def fetch_wordlist():
    all_words = []
    for api_url in API_WORDLISTS:
        try:
            print(Fore.YELLOW + f"[*] Fetching API wordlist: {api_url}")
            res = requests.get(api_url, timeout=10)
            res.raise_for_status()
            all_words.extend(res.text.splitlines())
        except Exception as e:
            print(Fore.RED + f"[!] Failed to fetch from API: {e}")
    return list(set(all_words))

def extract_paths_from_js(content):
    return re.findall(r'/[a-zA-Z0-9_/\.-]+', content)

def scan_url(base_url, path, extensions):
    results = []
    for ext in extensions:
        target = urljoin(base_url, path.strip() + ext)
        headers = {'User-Agent': random.choice(UA_LIST)}

        try:
            res = requests.get(target, headers=headers, timeout=3, allow_redirects=False)
            code = res.status_code
            size = len(res.content)
            location = res.headers.get("Location", "")

            if code == 200:
                print(Fore.GREEN + f"[200 OK] {target} ({size} bytes)")
                SUMMARY["200"] += 1
                results.append(f"[200] {target}")
                if target.endswith(".js"):
                    js_paths = extract_paths_from_js(res.text)
                    for jp in js_paths:
                        print(Fore.CYAN + f"[JS] Found path in JS: {jp}")
            elif code == 403:
                print(Fore.YELLOW + f"[403 Forbidden] {target}")
                SUMMARY["403"] += 1
                results.append(f"[403] {target}")
            elif code in [301, 302]:
                print(Fore.CYAN + f"[{code}] {target} -> {location}")
                SUMMARY[str(code)] += 1
                results.append(f"[{code}] {target} -> {location}")
        except requests.RequestException:
            pass
    return results

def recursive_scan(base_url, words, extensions, depth, current_depth):
    if current_depth > depth:
        return

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_url, base_url, word, extensions): word for word in words}
        for future in tqdm(as_completed(futures), total=len(futures)):
            result = future.result()
            if result:
                FOUND.extend(result)

    next_paths = [entry.split()[1] for entry in FOUND if entry.endswith('/')]
    for new_base in next_paths:
        recursive_scan(new_base, words, extensions, depth, current_depth + 1)

def show_summary():
    print(Fore.MAGENTA + "\n===============================================================")
    print(Fore.CYAN + f"Scan Summary")
    print(Fore.MAGENTA + f"Found Total: {len(FOUND)}")
    print(Fore.GREEN + f"200 OK: {SUMMARY['200']}")
    print(Fore.YELLOW + f"403 Forbidden: {SUMMARY['403']}")
    print(Fore.BLUE + f"301 Redirects: {SUMMARY['301']}")
    print(Fore.BLUE + f"302 Redirects: {SUMMARY['302']}")
    print(Fore.MAGENTA + "===============================================================")

def main():
    print(Fore.MAGENTA + "\n🎯 DirVader-Ultimate v3.2 – Fully Auto, Fast Scan & Terminal Only")
    url = input("🔗 Enter target URL (e.g. https://example.com): ").strip()
    extensions = ["", ".php", ".html", ".bak", ".zip", ".js"]
    depth = 2

    print(Fore.BLUE + "\n📥 Loading wordlists from trusted APIs...")
    words = fetch_wordlist()

    print(Fore.CYAN + f"\n🚀 Scanning started on: {url} with recursion depth {depth}\n")
    recursive_scan(url, words, extensions, depth, 1)

    print(Fore.MAGENTA + f"\n✅ Scan completed! Total found: {len(FOUND)}")
    show_summary()

if __name__ == "__main__":
    main()