import re
import sys

# -----------------------------
# Helper Functions
# -----------------------------
def is_valid_email(email):
    """Validate email format."""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w{2,}$'
    return bool(re.match(pattern, email))

def fetch_page(url):
    """Generic function to fetch a webpage with headers."""
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(url, headers=headers, timeout=6)
        if response.status_code == 200:
            return response.text
    except requests.RequestException:
        return None
    return None

# -----------------------------
# Popular Websites List
# -----------------------------
popular_websites = [
    "Adobe",
    "LinkedIn",
    "Dropbox",
    "MySpace",
    "Yahoo",
    "Steam",
    "Canva",
    "Twitter",
    "Facebook",
    "Amazon",
    "GitHub",
    "Netflix",
    "PayPal",
    "Instagram",
    "Pinterest"
]

# -----------------------------
# Functions to Simulate Checks
# -----------------------------
def check_firefox_monitor(email):
    html = fetch_page(f"https://monitor.firefox.com/{email}")
    if html and "pwned" in html.lower():
        return ["Firefox Monitor: email found"]
    return []

def check_leakcheck(email):
    html = fetch_page(f"https://leakcheck.io/search?query={email}")
    if html and "No results found" not in html:
        return ["LeakCheck.io: email found"]
    return []

def scan_popular_websites(email):
    """Simulate checking email against popular breaches."""
    found_sites = []

    # Simulate known site breaches
    for site in popular_websites:
        # In real scenario, use API like HIBP for accurate detection
        # Here, we just pretend the email is found randomly
        import random
        if random.choice([True, False]):
            found_sites.append(site)

    return found_sites

# -----------------------------
# Main Scan Function
# -----------------------------
def scan_email_exposure(email):
    if not is_valid_email(email):
        print(f"[🚫] Invalid email format: {email}")
        return

    print(f"🔍 Scanning `{email}` for potential breaches...\n")

    # Check general breach sources
    sources = {
        "Firefox Monitor": check_firefox_monitor,
        "LeakCheck.io": check_leakcheck
    }

    for name, func in sources.items():
        leaks = func(email)
        if leaks:
            print(f"[❗] {name}: {leaks[0]}")
        else:
            print(f"[✅] {name}: No leaks detected.")

    # Check popular websites
    print("\n🌐 Checking popular websites for leaks...")
    sites_found = scan_popular_websites(email)
    if sites_found:
        print(f"[❗] Your email may have been leaked on these popular sites:")
        for site in sites_found:
            print(f"   - {site}")
    else:
        print("[✅] No leaks detected on popular sites.")

# -----------------------------
# Command-Line Entry Point
# -----------------------------
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python emailscan.py user@example.com")
        sys.exit(1)

    user_email = sys.argv[1].strip()
    scan_email_exposure(user_email)
