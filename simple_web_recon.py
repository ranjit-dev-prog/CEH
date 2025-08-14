import socket
import requests
import subprocess
import re
import argparse
from urllib.parse import urlparse
import tldextract
import whois

def get_a_records(domain):
    try:
        return socket.gethostbyname_ex(domain)[2]
    except Exception:
        return []

def get_mx_records(domain):
    try:
        result = subprocess.run(['nslookup', '-type=mx', domain], capture_output=True, text=True, timeout=5)
        return [line.split('=')[-1].strip() for line in result.stdout.splitlines() if 'mail exchanger' in line.lower()]
    except Exception:
        return []

def get_ns_records(domain):
    try:
        result = subprocess.run(['nslookup', '-type=ns', domain], capture_output=True, text=True, timeout=5)
        return [line.split('=')[-1].strip() for line in result.stdout.splitlines() if 'nameserver' in line.lower()]
    except Exception:
        return []

def is_suspicious_url(url):
    flags = ['@', '.exe', '.zip', 'phishing', 'malware', 'login', 'update', 'verify', 'account', 'bank', 'paypal', 'free', 'click', 'confirm', 'cmd=']
    return any(flag in url.lower() for flag in flags)

def is_masked_url(url):
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, domain): return True

    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly', 'adf.ly']
    if domain in shorteners: return True

    if re.search(r'%[0-9a-fA-F]{2}', url): return True
    return False

def get_hosting_provider(ip):
    try:
        w = whois.whois(ip)
        org = w.org or w.name or w.netname or w.responsible or w.address
        return org if org else "Unknown"
    except Exception:
        return "Unknown"

def get_http_headers(url):
    try:
        response = requests.get(url, timeout=10)
        return dict(response.headers)
    except Exception:
        return {}

def analyze_url(url):
    if not url.startswith("https://"):
        print("❌ Only HTTPS URLs are accepted.")
        return

    suspicious = is_suspicious_url(url)
    masked = is_masked_url(url)

    print(f"\n🔍 Scanning URL: {url}")
    print(f"Suspicious URL: {'Yes' if suspicious else 'No'}")
    print(f"Masked URL: {'Yes' if masked else 'No'}")

    if suspicious or masked:
        print("⚠️ URL is flagged. Skipping further DNS analysis.\n")
        return

    parsed = urlparse(url)
    domain = parsed.hostname

    print(f"🌐 Domain: {domain}")

    a_records = get_a_records(domain)
    print(f"🔢 A Records: {a_records or 'None found'}")

    mx_records = get_mx_records(domain)
    print(f"📮 MX Records: {mx_records or 'None found'}")

    ns_records = get_ns_records(domain)
    print(f"🛰️ NS Records: {ns_records or 'None found'}")

    ip = a_records[0] if a_records else None
    hosting = get_hosting_provider(ip) if ip else 'Unknown'
    print(f"🏢 Hosting Provider: {hosting}")

    headers = get_http_headers(url)
    print(f"\n📝 HTTP Response Headers:")
    for k, v in headers.items():
        print(f"  {k}: {v}")

    print("\n📊 Risk Summary:")
    risk_status = "Yes" if not mx_records or not ns_records or hosting == 'Unknown' else "No"
    print(f"Suspicious: {'Yes' if suspicious else 'No'}")
    print(f"Masked: {'Yes' if masked else 'No'}")
    print(f"Missing MX or NS: {'Yes' if not mx_records or not ns_records else 'No'}")
    print(f"Risk Status: {risk_status}")

    if risk_status == "Yes":
        print("🚨 This website might be risky. Proceed with caution.\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web Recon & DNS Info Tool")
    parser.add_argument("url", help="Enter the HTTPS URL to analyze")
    args = parser.parse_args()
    analyze_url(args.url)
