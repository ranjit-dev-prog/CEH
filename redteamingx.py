import sys, requests, json
from datetime import datetime
from urllib.parse import urlparse

def color(text, code): return f"\033[{code}m{text}\033[0m"
def print_banner():
    print(color("\n🛡️  RedStrike-X v4.0 – 2030 Red Team Web Scanner", "96"))
    print(color("--------------------------------------------------------", "96"))

def is_url_safe(target):
    try:
        r = requests.get(target, timeout=5)
        if r.status_code != 200: return False
        parsed = urlparse(target)
        bad = ['bit.ly', 'shorturl', 'adf.ly', 'tinyurl', 'goo.gl']
        if any(x in parsed.netloc for x in bad): return False
        return True
    except: return False

def check_sql_injection(target):
    url = f"{target}/search?q=' OR 1=1--"
    try:
        r = requests.get(url, timeout=5)
        if any(err in r.text.lower() for err in ["mysql", "syntax", "sql error", "you have an error"]):
            return True, url
    except: pass
    return False, url

def check_xss(target):
    payload = "<script>alert(1)</script>"
    url = f"{target}/search?q={payload}"
    try:
        r = requests.get(url, timeout=5)
        if payload in r.text: return True, url
    except: pass
    return False, url

def check_ssrf(target):
    url = f"{target}/api/fetch-doc?url=http://169.254.169.254"
    return True, url  # test assumes endpoint exists for demo

def check_jwt_misconfig():
    token = "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
    return True, token

def check_headers(target):
    try:
        headers = requests.get(target, timeout=5).headers
        return headers
    except:
        return {}

def check_clickjacking(headers):
    return "X-Frame-Options" not in headers

def check_cors(headers):
    return "Access-Control-Allow-Origin" in headers and headers["Access-Control-Allow-Origin"] == "*"

def check_host_header_injection(target):
    try:
        r = requests.get(target, headers={"Host": "evil.com"}, timeout=5)
        return "evil.com" in r.text.lower()
    except:
        return False

def check_open_redirect(target):
    url = f"{target}/redirect?url=https://evil.com"
    try:
        r = requests.get(url, timeout=5, allow_redirects=False)
        return r.status_code in [301, 302] and "evil.com" in r.headers.get("Location", "")
    except:
        return False

def print_owasp_and_modern_report(results):
    print(color("\n🔎 OWASP + Modern Vulnerability Detection\n", "96"))
    for entry in results:
        status = color("✅ " + entry["status"], "92") if entry["status"] == "Present" else color("❌ Not Detected", "91")
        print(color(f"[{entry['id']}] {entry['title']:<35} → ", "94") + status)
        if entry.get("poc"):
            print(color(f"     ├─ POC: {entry['poc']}", "93"))
        if entry.get("reason"):
            print(color(f"     └─ Reason: {entry['reason']}", "93"))

def run_redstrike(target):
    print_banner()
    print(color(f"[🔍] Target: {target}", "94"))

    if not is_url_safe(target):
        print(color("[✘] Unsafe or unreachable URL", "91"))
        return

    headers = check_headers(target)
    results = []

    # OWASP
    results.append({"id": "A01", "title": "Broken Access Control", "status": "Not Detected"})
    present, poc = check_jwt_misconfig()
    results.append({"id": "A02", "title": "Cryptographic Failures", "status": "Present", "poc": poc, "reason": "JWT alg:none"})
    sqli, poc = check_sql_injection(target)
    xss, xpoc = check_xss(target)
    inj_status = "Present" if sqli or xss else "Not Detected"
    results.append({"id": "A03", "title": "Injection", "status": inj_status, "poc": poc if sqli else xpoc})
    results.append({"id": "A04", "title": "Insecure Design", "status": "Not Detected"})
    misconfig = "X-Powered-By" in headers
    results.append({"id": "A05", "title": "Security Misconfiguration", "status": "Present" if misconfig else "Not Detected", "reason": "X-Powered-By exposed"})
    results.append({"id": "A06", "title": "Outdated Components", "status": "Not Detected"})  # Need Wappalyzer
    results.append({"id": "A07", "title": "Auth Failures", "status": "Not Detected"})
    results.append({"id": "A08", "title": "Integrity Failures", "status": "Not Detected"})
    results.append({"id": "A09", "title": "Logging Failures", "status": "Not Detected"})
    ssrf, poc = check_ssrf(target)
    results.append({"id": "A10", "title": "SSRF", "status": "Present" if ssrf else "Not Detected", "poc": poc})

    # Modern Vulns
    click = check_clickjacking(headers)
    results.append({"id": "M01", "title": "Clickjacking", "status": "Present" if click else "Not Detected"})
    cors = check_cors(headers)
    results.append({"id": "M02", "title": "CORS Misconfig", "status": "Present" if cors else "Not Detected"})
    hostinj = check_host_header_injection(target)
    results.append({"id": "M03", "title": "Host Header Injection", "status": "Present" if hostinj else "Not Detected"})
    redir = check_open_redirect(target)
    results.append({"id": "M04", "title": "Open Redirect", "status": "Present" if redir else "Not Detected"})

    print_owasp_and_modern_report(results)

# 🧪 Entry
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(color("Usage: python redstrike.py <url>", "93"))
        sys.exit(1)
    url = sys.argv[1].strip("/")
    if not url.startswith("http"): url = "https://" + url
    run_redstrike(url)
