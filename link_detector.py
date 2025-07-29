import socket
import ssl
import requests
from urllib.parse import urlparse
import datetime
import zoneinfo
import whois
import dns.resolver
import re
import sys

def parse_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Invalid URL format")
    return parsed

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def get_ssl_expiry(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert.get('notAfter')
    except Exception:
        return None

def ssl_status(expiry_str):
    if not expiry_str:
        return "No SSL certificate or not HTTPS"
    try:
        expiry_date = datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
        now = datetime.datetime.now(tz=zoneinfo.ZoneInfo("UTC"))
        return f"Valid (expires on {expiry_str})" if expiry_date > now else f"Expired (expired on {expiry_str})"
    except Exception:
        return "Unknown SSL certificate status"

def get_hosting_provider(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code == 200:
            return response.json().get('org', 'Unknown')
        return "Unknown"
    except:
        return "Unknown"

def get_whois_info(domain):
    try:
        return whois.whois(domain)
    except:
        return None

def get_dns_records(domain):
    records = {}
    types = ['A', 'MX', 'NS']
    for t in types:
        try:
            answers = dns.resolver.resolve(domain, t)
            records[t] = [r.to_text() for r in answers]
        except:
            records[t] = []
    return records

def is_suspicious_url(url):
    patterns = [
        r'@', r'//.*//', r'\.exe$', r'\.zip$', r'\.scr$', r'phishing',
        r'malware', r'login', r'update', r'verify', r'account', r'bank',
        r'paypal', r'free', r'click', r'confirm', r'webscr', r'cmd=', r'\?'
    ]
    return any(re.search(p, url, re.IGNORECASE) for p in patterns)

def is_masked_url(url):
    domain = urlparse(url).netloc
    ip_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd']
    if re.match(ip_pattern, domain) or any(s in domain for s in shorteners):
        return True
    return bool(re.search(r'%[0-9a-fA-F]{2}', url))

def is_parked_domain(whois_info):
    if not whois_info:
        return False
    creation = whois_info.creation_date
    if isinstance(creation, list):
        creation = creation[0]
    if creation:
        age = (datetime.datetime.now() - creation).days
        if age < 30:
            return True
    registrar = whois_info.registrar
    return registrar and 'parking' in str(registrar).lower()

def is_spam_domain(dns_records):
    mx = dns_records.get('MX', [])
    if not mx:
        return False
    return any(any(s in record.lower() for s in ['spam', 'blacklist', 'block']) for record in mx)

def main():
    # --- Input: command-line or prompt ---
    if len(sys.argv) > 1:
        url_input = sys.argv[1]
    else:
        url_input = input("🔗 Enter URL to analyze: ").strip()

    try:
        parsed = parse_url(url_input)
    except ValueError as e:
        print(f"❌ {e}")
        return

    domain = parsed.netloc
    print(f"\n🔍 Domain: {domain}")

    # IP Resolution
    ip = resolve_ip(domain)
    print(f"🌐 IP Address: {ip if ip else 'Could not resolve'}")

    # SSL
    ssl_info = get_ssl_expiry(domain) if parsed.scheme == 'https' else None
    print(f"🔐 SSL Certificate Status: {ssl_status(ssl_info)}")

    # Hosting
    print(f"🏢 Hosting Provider: {get_hosting_provider(ip) if ip else 'Unknown'}")

    # WHOIS
    whois_info = get_whois_info(domain)
    if whois_info:
        print("\n📜 WHOIS Info:")
        print(f"   ▫ Registrar: {whois_info.registrar}")
        print(f"   ▫ Created: {whois_info.creation_date}")
        print(f"   ▫ Expires: {whois_info.expiration_date}")
    else:
        print("📜 WHOIS Info: Not available")

    # DNS
    dns_records = get_dns_records(domain)
    print("\n📡 DNS Records:")
    for k, v in dns_records.items():
        print(f"   ▫ {k}: {v if v else 'None'}")

    # Heuristic Analysis
    suspicious = is_suspicious_url(url_input)
    masked = is_masked_url(url_input)
    parked = is_parked_domain(whois_info)
    spam = is_spam_domain(dns_records)

    print("\n⚠️ Risk Indicators:")
    print(f"   ▫ Suspicious URL: {'Yes' if suspicious else 'No'}")
    print(f"   ▫ Masked URL: {'Yes' if masked else 'No'}")
    print(f"   ▫ Parked Domain: {'Yes' if parked else 'No'}")
    print(f"   ▫ Spam Domain: {'Yes' if spam else 'No'}")

    overall = "Risky" if any([suspicious, masked, parked, spam]) else "Safe"
    print(f"\n🧠 Overall Risk Status: {overall}")

    if suspicious:
        print("   ▫ Malware Detected: Yes")
        print("   ▫ Phishing Detected: Yes")
    else:
        print("   ▫ Malware Detected: No")
        print("   ▫ Phishing Detected: No")

if __name__ == "__main__":
    main()
