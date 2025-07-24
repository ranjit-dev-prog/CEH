import ssl
import socket
from urllib.parse import urlparse
import datetime
import idna
import warnings

# Suppress UTC warning for now
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

    # Convert cert dates
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

def main():
    url = input("🔐 Enter HTTPS URL to check certificate: ").strip()

    if not is_https_url(url):
        print("❌ This tool only supports HTTPS URLs for SSL checking.")
        return

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        hostname = idna.encode(hostname).decode('utf-8')  # IDN support
        print(f"🔍 Checking certificate for: {hostname}")
        
        cert = get_certificate_info(hostname)
        cert_info = validate_certificate(cert)

        print("\n🔐 Certificate Info:")
        print(f"   🔹 Issued To: {cert_info['issued_to']}")
        print(f"   🔹 Issued By: {cert_info['issued_by']}")
        print(f"   📅 Valid From: {cert_info['valid_from']}")
        print(f"   📅 Valid Until: {cert_info['valid_until']}")
        
        if cert_info['is_valid']:
            print("✅ Certificate is valid.")
        else:
            print("❌ Certificate is INVALID or EXPIRED.")
    
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
