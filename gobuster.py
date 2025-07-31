# DirVader-Ultimate v2.1

import requests
import argparse
import os
import random
import re
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, init
from tqdm import tqdm
import time

init(autoreset=True)

FOUND = []
PROXIES = []
HEADERS = []
UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
]

API_WORDLISTS = [
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
    "https://wordlists.assetnote.io/data/manual/common.txt"
]

def fetch_wordlist(source):
    if source == "api":
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

    elif source.startswith("http"):
        try:
            print(Fore.YELLOW + f"[*] Downloading wordlist from: {source}")
            res = requests.get(source, timeout=10)
            res.raise_for_status()
            return res.text.splitlines()
        except Exception as e:
            print(Fore.RED + f"[!] Failed to download: {e}")
            return []
    elif os.path.exists(source):
        with open(source, "r", encoding="utf-8", errors="ignore") as f:
            return f.read().splitlines()
    else:
        print(Fore.RED + f"[!] Invalid wordlist path or URL: {source}")
        return []

def extract_paths_from_js(content):
    return re.findall(r'/[a-zA-Z0-9_/\.-]+', content)

def scan_url(base_url, path, extensions, timeout, proxies, verbose, extract_js, headers):
    for ext in extensions:
        target = urljoin(base_url, path.strip() + ext)
        hdrs = headers or {'User-Agent': random.choice(UA_LIST)}
        proxy = random.choice(proxies) if proxies else None

        try:
            res = requests.get(target, headers=hdrs, timeout=timeout, allow_redirects=False, proxies=proxy)
            code = res.status_code
            size = len(res.content)
            location = res.headers.get("Location", "")

            if code == 200:
                print(Fore.GREEN + f"[200 OK] {target} ({size} bytes)")
                FOUND.append(f"[200] {target}")
                if extract_js and target.endswith(".js"):
                    js_paths = extract_paths_from_js(res.text)
                    for jp in js_paths:
                        print(Fore.CYAN + f"[JS] Found path in JS: {jp}")
            elif code == 403:
                print(Fore.YELLOW + f"[403 Forbidden] {target}")
                FOUND.append(f"[403] {target}")
            elif code in [301, 302]:
                print(Fore.CYAN + f"[{code}] {target} -> {location}")
                FOUND.append(f"[{code}] {target} -> {location}")
            elif verbose and code not in [404, 400, 500]:
                print(Fore.BLUE + f"[{code}] {target}")
                FOUND.append(f"[{code}] {target}")
        except requests.RequestException:
            if verbose:
                print(Fore.RED + f"[ERR] Failed: {target}")

def recursive_scan(base_url, words, extensions, timeout, proxies, verbose, extract_js, depth, current_depth, headers):
    if current_depth > depth:
        return

    with ThreadPoolExecutor(max_workers=30) as executor:
        list(tqdm(executor.map(lambda w: scan_url(base_url, w, extensions, timeout, proxies, verbose, extract_js, headers), words), total=len(words)))

    next_paths = [entry.split()[1] for entry in FOUND if entry.endswith('/')]
    for new_base in next_paths:
        recursive_scan(new_base, words, extensions, timeout, proxies, verbose, extract_js, depth, current_depth + 1, headers)

def load_proxies(file_path):
    proxies = []
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            for line in f:
                p = line.strip()
                proxies.append({"http": p, "https": p})
    return proxies

def parse_headers(header_string):
    headers = {}
    for item in header_string.split(';'):
        if ':' in item:
            k, v = item.split(':', 1)
            headers[k.strip()] = v.strip()
    return headers

def main():
    parser = argparse.ArgumentParser(description="DirVader-Ultimate v2.1: Auth, JS, WAF Bypass, Online/API Wordlist")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist file, URL or use 'api' for default APIs")
    parser.add_argument("-x", "--extensions", default=".php,.html,.bak,.zip,", help="Comma-separated extensions")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Request timeout")
    parser.add_argument("-o", "--output", help="Save found paths to file")
    parser.add_argument("--proxy", help="Proxy list file (http://ip:port)")
    parser.add_argument("--verbose", action="store_true", help="Show all status codes")
    parser.add_argument("--extract-js", action="store_true", help="Parse JS files for hidden paths")
    parser.add_argument("--depth", type=int, default=1, help="Recursion depth")
    parser.add_argument("--headers", help="Add headers (e.g. Authorization: Bearer xyz; Cookie: key=value)")
    args = parser.parse_args()

    extensions = args.extensions.split(',')
    words = fetch_wordlist(args.wordlist)

    global PROXIES, HEADERS
    if args.proxy:
        PROXIES = load_proxies(args.proxy)
    if args.headers:
        HEADERS = parse_headers(args.headers)

    recursive_scan(args.url, words, extensions, args.timeout, PROXIES, args.verbose, args.extract_js, args.depth, 1, HEADERS)

    if args.output:
        with open(args.output, "w") as f:
            for entry in FOUND:
                f.write(entry + "\n")
        print(Fore.MAGENTA + f"[✓] Results saved to {args.output}")

if __name__ == "__main__":
    main()
