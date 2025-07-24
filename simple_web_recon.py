import socket
import requests
from urllib.parse import urlparse
import re
import tldextract

def get_a_records(domain):
    try:
        return socket.gethostbyname_ex(domain)[2]
    except Exception:
        return []

def get_mx_records(domain):
    # Minimal MX record check using nslookup command (requires system call)
    import subprocess
    try:
        result = subprocess.run(['nslookup', '-type=mx', domain], capture_output=True, text=True, timeout=5)
        mx_records = []
        for line in result.stdout.splitlines():
            # nslookup output line example: "example.com    mail exchanger = mx1.example.com"
            if 'mail exchanger' in line.lower():
                parts = line.split('mail exchanger =')
                if len(parts) > 1:
                    mx = parts[1].strip()
                    mx_records.append(mx)
        return mx_records
    except Exception:
        return []

def get_ns_records(domain):
    # Minimal NS record check using nslookup command (requires system call)
    import subprocess
    try:
        result = subprocess.run(['nslookup', '-type=ns', domain], capture_output=True, text=True, timeout=5)
        ns_records = []
        for line in result.stdout.splitlines():
            # nslookup output line example: "example.com    nameserver = ns1.example.com"
            if 'nameserver' in line.lower():
                parts = line.split('nameserver =')
                if len(parts) > 1:
                    ns = parts[1].strip()
                    ns_records.append(ns)
        return ns_records
    except Exception:
        return []

def get_hosting_provider(ip):
    # Use ipinfo.io public API to get org info
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/org', timeout=5)
        if response.status_code == 200:
            return response.text.strip()
        else:
            return 'Unknown'
    except Exception:
        return 'Unknown'

def is_suspicious_url(url):
    suspicious_keywords = ['@', '.exe', '.zip', 'phishing', 'malware', 'login', 'update', 'verify', 'account', 'bank', 'paypal', 'free', 'click', 'confirm', 'cmd=', '?']
    for keyword in suspicious_keywords:
        if keyword.lower() in url.lower():
            return True
    return False

def is_masked_url(url):
    # Use tldextract to parse domain parts
    extracted = tldextract.extract(url)
    domain = extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain

    # Check if domain is IP address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, domain):
        return True

    # Check for URL shorteners
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly', 'adf.ly']
    if domain in shorteners:
        return True

    # Check for hex encoding in URL
    if re.search(r'%[0-9a-fA-F]{2}', url):
        return True

    return False

def main():
    url_input = input("Enter HTTPS URL: ").strip()
    if not url_input.startswith('https://'):
        print("Only HTTPS URLs are accepted. Exiting.")
        return

    suspicious = is_suspicious_url(url_input)
    masked = is_masked_url(url_input)

    print(f"Suspicious URL: {'Yes' if suspicious else 'No'}")
    print(f"Masked URL: {'Yes' if masked else 'No'}")

    if suspicious or masked:
        print("URL is suspicious or masked. Stopping further analysis.")
        return

    parsed = urlparse(url_input)
    domain = parsed.netloc

    print(f"Domain: {domain}")

    a_records = get_a_records(domain)
    print(f"A Records: {a_records}")

    mx_records = get_mx_records(domain)
    print(f"MX Records: {mx_records}")

    ns_records = get_ns_records(domain)
    print(f"NS Records: {ns_records}")

    ip = a_records[0] if a_records else None
    hosting = get_hosting_provider(ip) if ip else 'Unknown'
    print(f"Hosting Provider: {hosting}")

    print("\nSummary of Analysis:")
    print(f"URL: {url_input}")
    print(f"Domain: {domain}")
    print(f"A Records: {a_records}")
    print(f"MX Records: {mx_records}")
    print(f"NS Records: {ns_records}")
    print(f"Hosting Provider: {hosting}")

    # Determine risk status based on missing MX, NS, or hosting info
    risk_status = "No"
    if not mx_records or not ns_records or hosting == 'Unknown':
        risk_status = "Yes"

    print(f"Suspicious URL: {'Yes' if suspicious else 'No'}")
    print(f"Masked URL: {'Yes' if masked else 'No'}")
    print(f"Risk Status: {risk_status}")
    if risk_status == "Yes":
        print("Website might be risky or fake, please be careful.")
    
if __name__ == "__main__":
    main()
