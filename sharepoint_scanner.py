"""
SharePoint Scanner - URL Information and Technology Detection

Third-party Libraries:
- requests
- Wappalyzer (python-Wappalyzer)
- urllib3
- cryptography

Install with:
pip install requests python-Wappalyzer urllib3 cryptography
"""

import sys
import socket
import ssl
import datetime
import requests
import dns.resolver
from urllib.parse import urlparse

# Wappalyzer detection
try:
    from Wappalyzer import Wappalyzer, WebPage
    wappalyzer_available = True
except ImportError:
    print("Warning: python-Wappalyzer not found. Technology detection will be limited.")
    wappalyzer_available = False

# ------------------- Safety Check ------------------- #
def is_url_suspicious(url):
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        print("Invalid URL format.")
        return True

    suspicious_keywords = ['phishing', 'malware', 'attack', 'suspicious']
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            print(f"Suspicious keyword detected: {keyword}")
            return True

    try:
        host = parsed.netloc
        port = 443 if parsed.scheme == 'https' else 80
        with socket.create_connection((host, port), timeout=5):
            return False
    except Exception:
        print(f"Could not connect to {host}. Marked as suspicious.")
        return True

# ------------------- DNS Info ------------------- #
def get_dns_records(domain):
    dns_info = {}
    try:
        dns_info['A'] = [r.to_text() for r in dns.resolver.resolve(domain, 'A')]
    except:
        dns_info['A'] = []

    try:
        dns_info['AAAA'] = [r.to_text() for r in dns.resolver.resolve(domain, 'AAAA')]
    except:
        dns_info['AAAA'] = []

    try:
        dns_info['MX'] = [r.to_text() for r in dns.resolver.resolve(domain, 'MX')]
    except:
        dns_info['MX'] = []

    try:
        dns_info['NS'] = [r.to_text() for r in dns.resolver.resolve(domain, 'NS')]
    except:
        dns_info['NS'] = []

    return dns_info

# ------------------- IP and Hosting Info ------------------- #
def get_hosting_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except:
        return None

def get_hosting_provider(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.status_code == 200:
            return r.json().get("org", "Unknown")
    except:
        pass
    return "Unknown"

# ------------------- SSL Certificate ------------------- #
def get_certificate_expiry_date(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert.get('notAfter')
    except:
        return None

def get_certificate_status(expiry_str):
    if not expiry_str:
        return "Unknown"
    try:
        expiry_date = datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
        return "Valid" if expiry_date > datetime.datetime.utcnow() else "Expired"
    except:
        return "Unknown"

# ------------------- Technology Detection ------------------- #
def detect_technology(url):
    if wappalyzer_available:
        try:
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(url)
            return wappalyzer.analyze(webpage)
        except:
            return None
    else:
        try:
            r = requests.get(url, timeout=5)
            techs = set()
            if 'Server' in r.headers:
                techs.add(f"Server: {r.headers['Server']}")
            if 'X-Powered-By' in r.headers:
                techs.add(f"X-Powered-By: {r.headers['X-Powered-By']}")
            return techs if techs else None
        except:
            return None

# ------------------- Main Function ------------------- #
def main():
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <url>")
        sys.exit(1)

    user_input = sys.argv[1].strip()
    if not user_input.startswith('http://') and not user_input.startswith('https://'):
        user_input = 'http://' + user_input

    parsed = urlparse(user_input)
    hostname = parsed.netloc

    print(f"\n[*] Scanning: {user_input}\n")

    if is_url_suspicious(user_input):
        print("[!] URL is suspicious or unreachable. Exiting.")
        sys.exit(1)

    ip = get_hosting_ip(hostname)
    if not ip:
        print("[!] Could not resolve IP address. Exiting.")
        sys.exit(1)

    dns_info = get_dns_records(hostname)
    hosting_provider = get_hosting_provider(ip)

    cert_expiry = get_certificate_expiry_date(hostname) if parsed.scheme == 'https' else None
    cert_status = get_certificate_status(cert_expiry) if cert_expiry else "Not Applicable"

    techs = detect_technology(user_input)

    print("---------- Scan Report ----------")
    print(f"URL: {user_input}")
    print(f"Resolved IP: {ip}")
    print(f"Hosting Provider: {hosting_provider}")
    print(f"SSL Certificate Expiry: {cert_expiry if cert_expiry else 'N/A'}")
    print(f"SSL Certificate Status: {cert_status}")
    
    print("\nDNS Records:")
    for record_type, records in dns_info.items():
        print(f" {record_type} → {', '.join(records) if records else 'None'}")

    print("\nTechnologies Detected:")
    if techs:
        for tech in techs:
            print(f" - {tech}")
    else:
        print(" - No technology info available.")

# ------------------- Execute ------------------- #
if __name__ == "__main__":
    main()
