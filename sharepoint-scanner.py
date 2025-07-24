"""
Sharepoint Scanner - URL Information and Technology Detection

Required third-party libraries:
- requests
- Wappalyzer (python-Wappalyzer)
- urllib3
- cryptography

Install with:
pip install requests python-Wappalyzer urllib3 cryptography

"""

import socket
import ssl
import sys
from urllib.parse import urlparse
import requests

import requests

try:
    from Wappalyzer import Wappalyzer, WebPage
    wappalyzer_available = True
except ImportError:
    print("Warning: python-Wappalyzer module not found. Technology detection will be limited.")
    wappalyzer_available = False

def is_url_suspicious(url):
    """
    Perform a URL safety check to detect suspicious URLs.
    This example checks basic URL format and tries to connect.
    More advanced checks can be added as needed.
    """
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        print("Invalid URL format.")
        return True

    # Basic suspicious pattern checks (can be extended)
    suspicious_keywords = ['phishing', 'malware', 'attack', 'suspicious']
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            print(f"URL contains suspicious keyword: {keyword}")
            return True

    try:
        # Try to open a socket connection to the host on port 80 or 443
        host = parsed.netloc
        port = 443 if parsed.scheme == 'https' else 80
        sock = socket.create_connection((host, port), timeout=5)
        sock.close()
        return False
    except (socket.timeout, socket.error):
        print(f"Unable to connect to {host} on port {port}. URL considered suspicious or unreachable.")
        return True

import datetime

def get_certificate_expiry_date(hostname):
    """
    Retrieve SSL certificate expiry date for the given hostname.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry = cert.get('notAfter')
                return expiry
    except Exception as e:
        return None

def get_certificate_status(expiry_date_str):
    """
    Determine SSL certificate status based on expiry date string.
    Returns 'Valid' if expiry date is in the future, 'Expired' if past, or 'Unknown' if invalid.
    """
    if not expiry_date_str:
        return "Unknown"
    try:
        expiry_date = datetime.datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')
        now = datetime.datetime.utcnow()
        if expiry_date > now:
            return "Valid"
        else:
            return "Expired"
    except Exception:
        return "Unknown"

def get_hosting_provider(ip):
    """
    Query ipinfo.io API to get hosting provider information for the given IP address.
    """
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            org = data.get('org', 'Unknown')
            return org
        else:
            return "Unknown"
    except Exception:
        return "Unknown"

def get_hosting_ip(hostname):
    """
    Resolve the IP address of the hostname.
    """
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception as e:
        return None

def detect_technology(url):
    """
    Use Wappalyzer to detect technologies used by the website.
    If Wappalyzer is not available, fall back to basic detection from HTTP headers.
    """
    if wappalyzer_available:
        try:
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(url)
            technologies = wappalyzer.analyze(webpage)
            return technologies
        except Exception as e:
            return None
    else:
        # Basic detection from HTTP headers
        try:
            response = requests.get(url, timeout=5)
            server = response.headers.get('Server', 'Unknown')
            powered_by = response.headers.get('X-Powered-By', 'Unknown')
            techs = set()
            if server != 'Unknown':
                techs.add(f"Server: {server}")
            if powered_by != 'Unknown':
                techs.add(f"X-Powered-By: {powered_by}")
            return techs if techs else None
        except Exception:
            return None

def main():
    user_input = input("Enter the URL to scan (include http:// or https://): ").strip()
    if not user_input.startswith('http://') and not user_input.startswith('https://'):
        user_input = 'http://' + user_input

    if is_url_suspicious(user_input):
        print("URL is suspicious or unreachable. Aborting scan.")
        sys.exit(1)

    parsed_url = urlparse(user_input)
    hostname = parsed_url.netloc

    ip = get_hosting_ip(hostname)
    if not ip:
        print("Could not resolve IP address. Aborting.")
        sys.exit(1)

    cert_expiry = None
    cert_status = "Unknown"
    if parsed_url.scheme == 'https':
        cert_expiry = get_certificate_expiry_date(hostname)
        cert_status = get_certificate_status(cert_expiry)

    hosting_provider = get_hosting_provider(ip)

    technologies = detect_technology(user_input)

    print("\nScan Results:")
    print(f"URL: {user_input}")
    print(f"Hosting IP: {ip}")
    print(f"Hosting Provider: {hosting_provider}")
    if cert_expiry:
        print(f"Certificate Expiry Date: {cert_expiry}")
        print(f"Certificate Status: {cert_status}")
    else:
        print("Certificate Expiry Date: Not available or not HTTPS")
        print("Certificate Status: Not available or not HTTPS")
    if technologies:
        print("Technologies Detected:")
        for tech in technologies:
            print(f" - {tech}")
    else:
        print("Technologies Detected: Not available")

if __name__ == "__main__":
    main()
