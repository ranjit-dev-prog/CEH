import ssl
import socket
import sys
from urllib.parse import urlparse
import datetime
import idna
import warnings

# Suppress deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

def is_https_url(url):
    return url.lower().startswith("https://")

def get_certificate_info(hostname):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            return cert

def validate_certificate(cert):
    subject = cert.get('subject', [])
    issuer = cert.get('issuer', [])
    not_before = cert.get('notBefore')
    not_after = cert.get('notAfter')

    fmt = "%b %d %H:%M:%S %Y %Z"
    start_date = datetime.datetime.strptime(not_before, fmt)
    exp_date = datetime.datetime.strptime(not_after, fmt)
    now = datetime.datetime.utcnow()

    is_valid = start_date <= now <= exp_date

    return {
        "issued_to": subject,
        "issued_by": issuer,
        "valid_from": start_date,
        "valid_until": exp_date,
        "is_valid": is_valid
    }

def print_cert_info(cert_info):
    print("\n🔐 Certificate Info:")
    print(f"   🔹 Issued To: {cert_info['issued_to']}")
    print(f"   🔹 Issued By: {cert_info['issued_by']}")
    print(f"   📅 Valid From: {cert_info['valid_from']}")
    print(f"   📅 Valid Until: {cert_info['valid_until']}")
    
    if cert_info['is_valid']:
        print("✅ Certificate is valid.")
    else:
        print("❌ Certificate is INVALID or EXPIRED.")

def main():
    if len(sys.argv) != 2:
        print("Usage: python httpscheck.py https://example.com")
        return

    url = sys.argv[1].strip()

    if not is_https_url(url):
        print("❌ Only HTTPS URLs are supported.")
        return

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        hostname = idna.encode(hostname).decode('utf-8')  # IDN-safe
        print(f"🔍 Checking SSL certificate for: {hostname}")

        cert = get_certificate_info(hostname)
        cert_info = validate_certificate(cert)
        print_cert_info(cert_info)

    except socket.gaierror:
        print("❌ Could not resolve hostname.")
    except socket.timeout:
        print("❌ Connection timed out.")
    except ssl.SSLError as e:
        print(f"❌ SSL Error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
