import socket
import ssl
import requests
from urllib.parse import urlparse
import datetime
import zoneinfo
import whois
import dns.resolver
import re

def parse_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Invalid URL format")
    return parsed

def resolve_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception:
        return None

def get_ssl_expiry(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry = cert.get('notAfter')
                return expiry
    except Exception:
        return None

def ssl_status(expiry_str):
    if not expiry_str:
        return "No SSL certificate or not HTTPS"
    try:
        expiry_date = datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
        now = datetime.datetime.now(tz=zoneinfo.ZoneInfo("UTC"))
        if expiry_date > now:
            return f"Valid (expires on {expiry_str})"
        else:
            return f"Expired (expired on {expiry_str})"
    except Exception:
        return "Unknown SSL certificate status"

def get_hosting_provider(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get('org', 'Unknown')
        else:
            return "Unknown"
    except Exception:
        return "Unknown"

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception:
        return None

def get_dns_records(domain):
    records = {}
    try:
        answers = dns.resolver.resolve(domain, 'A')
        records['A'] = [r.to_text() for r in answers]
    except Exception:
        records['A'] = []
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        records['MX'] = [r.to_text() for r in answers]
    except Exception:
        records['MX'] = []
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        records['NS'] = [r.to_text() for r in answers]
    except Exception:
        records['NS'] = []
    try:
        answers = dns.resolver.resolve(domain, 'IDN')
        records['IDN'] = [r.to_text() for r in answers]
    except Exception:
        records['IDN'] = []
    return records

def is_suspicious_url(url):
    suspicious_patterns = [
        r'@',  # URL contains @ symbol
        r'//.*//',  # multiple double slashes
        r'\.exe$',  # executable file
        r'\.zip$',  # zip file
        r'\.scr$',  # screensaver file
        r'phishing',  # keyword phishing
        r'malware',  # keyword malware
        r'login',  # keyword login
        r'update',  # keyword update
        r'verify',  # keyword verify
        r'account',  # keyword account
        r'bank',  # keyword bank
        r'paypal',  # keyword paypal
        r'free',  # keyword free
        r'click',  # keyword click
        r'confirm',  # keyword confirm
        r'webscr',  # keyword webscr
        r'cmd=',  # command injection
        r'\?',  # query parameters
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False

def is_masked_url(url):
    # Detect if URL is masked using IP address or hex encoding or URL shorteners
    parsed = urlparse(url)
    domain = parsed.netloc
    ip_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
    if re.match(ip_pattern, domain):
        return True
    if re.search(r'%[0-9a-fA-F]{2}', url):
        return True
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly', 'adf.ly']
    for short in shorteners:
        if short in domain:
            return True
    return False

def is_parked_domain(whois_info):
    if not whois_info:
        return False
    creation_date = whois_info.creation_date
    registrar = whois_info.registrar
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if creation_date:
        age_days = (datetime.datetime.now() - creation_date).days
        if age_days < 30:
            return True
    if registrar and 'parking' in registrar.lower():
        return True
    return False

def is_spam_domain(dns_records):
    mx_records = dns_records.get('MX', [])
    if not mx_records:
        return False  # No MX records alone does not mean spam
    suspicious_mx = ['spam', 'blacklist', 'block']
    for mx in mx_records:
        for s in suspicious_mx:
            if s in mx.lower():
                return True
    return False

def main():
    print("Link Detector - Domain Info, IP, Malware, Phishing, Parked Domain, Spam Status")
    url_input = input("Enter URL: ").strip()
    try:
        parsed = parse_url(url_input)
    except ValueError as e:
        print(f"Error: {e}")
        return

    domain = parsed.netloc
    print(f"\nDomain: {domain}")

    ip = resolve_ip(domain)
    if ip:
        print(f"IP Address: {ip}")
    else:
        print("IP Address: Could not resolve")

    ssl_expiry = None
    ssl_stat = "Not HTTPS or no SSL"
    if parsed.scheme == 'https':
        ssl_expiry = get_ssl_expiry(domain)
        ssl_stat = ssl_status(ssl_expiry)
    print(f"SSL Certificate Status: {ssl_stat}")

    hosting_provider = get_hosting_provider(ip) if ip else "Unknown"
    print(f"Hosting Provider: {hosting_provider}")

    whois_info = get_whois_info(domain)
    if whois_info:
        print("\nWHOIS Information:")
        print(f"  Registrar: {whois_info.registrar}")
        print(f"  Creation Date: {whois_info.creation_date}")
        print(f"  Expiration Date: {whois_info.expiration_date}")
        print(f"  Name Servers: {whois_info.name_servers}")
    else:
        print("\nWHOIS Information: Not available")

    dns_records = get_dns_records(domain)
    print("\nDNS Records:")
    print(f"  A Records: {dns_records.get('A', [])}")
    print(f"  MX Records: {dns_records.get('MX', [])}")
    print(f"  NS Records: {dns_records.get('NS', [])}")

    suspicious = is_suspicious_url(url_input)
    masked = is_masked_url(url_input)
    parked = is_parked_domain(whois_info)
    spam = is_spam_domain(dns_records)

    print("\nHeuristic Analysis:")
    print(f"  Suspicious URL: {'Yes' if suspicious else 'No'}")
    print(f"  Masked URL: {'Yes' if masked else 'No'}")
    print(f"  Parked Domain: {'Yes' if parked else 'No'}")
    print(f"  Spam Domain: {'Yes' if spam else 'No'}")

    risk_factors = [suspicious, masked, parked, spam]
    risk_status = "Risky" if any(risk_factors) else "Safe"
    print(f"\nOverall Risk Status: {risk_status}")

    if suspicious:
        print("  Malware Detected: Yes")
        print("  Phishing Detected: Yes")
    else:
        print("  Malware Detected: No")
        print("  Phishing Detected: No")

if __name__ == "__main__":
    main()
