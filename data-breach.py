import re
import requests
from bs4 import BeautifulSoup

def is_valid_email(email):
    """Validate email format"""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w{2,}$'
    return bool(re.match(pattern, email))

def check_firefox_monitor(email):
    """Simulate Firefox Monitor check"""
    try:
        url = f"https://monitor.firefox.com/{email}"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers, timeout=6)
        return "pwned" in response.text.lower()
    except:
        return None

def check_hunter_io(email):
    """Check if domain appears in hunter.io (scraped page)"""
    try:
        domain = email.split("@")[-1]
        url = f"https://hunter.io/search/{domain}"
        headers = {"User-Agent": "Mozilla/5.0"}
        resp = requests.get(url, headers=headers, timeout=6)
        return email in resp.text
    except:
        return None

def check_leakcheck(email):
    """Scrape LeakCheck.io result"""
    try:
        url = f"https://leakcheck.io/search?query={email}"
        headers = {"User-Agent": "Mozilla/5.0"}
        resp = requests.get(url, headers=headers, timeout=6)
        soup = BeautifulSoup(resp.text, "html.parser")
        return "No results found" not in resp.text
    except:
        return None

def check_intelx(email):
    """Simulate IntelX UI check"""
    try:
        url = f"https://intelx.io/?s={email}"
        headers = {"User-Agent": "Mozilla/5.0"}
        resp = requests.get(url, headers=headers, timeout=6)
        return email in resp.text
    except:
        return None

def scan_email_exposure(email):
    """Full scan and output builder"""
    if not is_valid_email(email):
        return f"[🚫] Invalid email format: `{email}`"

    print(f"🔍 Scanning `{email}` across breach  sources...\n")

    results = {
        "Firefox Monitor": check_firefox_monitor(email),
        "Hunter.io": check_hunter_io(email),
        "LeakCheck.io": check_leakcheck(email),
        "IntelX": check_intelx(email)
    }

    found = [k for k, v in results.items() if v is True]
    unknown = [k for k, v in results.items() if v is None]

    if found:
        print(f"[❗] Your email appears in known leaks ")
        print("🕶️ Risk level: Possible exposure on the dark web or public dump archives.\n")
    else:
        print(f"[✅] No exposure detected for `{email}` in monitored sources.\n")

    if unknown:
        print(f"[ℹ️] These sources couldn’t be checked: {', '.join(unknown)}")

# 🧪 Example CLI-style usage
if __name__ == "__main__":
    user_email = input("📬 Enter email to check: ").strip()
    scan_email_exposure(user_email)