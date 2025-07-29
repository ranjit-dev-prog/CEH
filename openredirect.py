import requests
import socket
import ssl
import sys
from urllib.parse import urlparse, urljoin

def is_valid_https_cert(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            if not cert:
                return False, "❌ No SSL certificate found"
            return True, f"✅ SSL Cert Valid Until: {cert['notAfter']}"
    except Exception as e:
        return False, f"❌ SSL Certificate Check Failed: {e}"

def has_suspicious_keywords(url):
    keywords = ['login', 'verify', 'bonus', 'free', 'win', 'secure', 'signin', 'paypal', 'update']
    return any(k in url.lower() for k in keywords)

def is_ip_address(domain):
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False

def is_url_safe(url):
    parsed = urlparse(url)

    if parsed.scheme != 'https':
        return False, "❌ URL is not using HTTPS"

    if is_ip_address(parsed.hostname):
        return False, "❌ URL uses IP address instead of domain"

    if has_suspicious_keywords(url):
        return False, "⚠️ Suspicious keywords found in URL"

    valid_cert, cert_msg = is_valid_https_cert(parsed.hostname)
    if not valid_cert:
        return False, cert_msg

    return True, "✅ URL passed all basic safety checks"

def test_open_redirect(base_url, payload="/?next=https://evil.com"):
    target = urljoin(base_url, payload)

    try:
        response = requests.get(target, allow_redirects=True, timeout=10)
        final_url = response.url
        if "evil.com" in final_url:
            return True, f"🔴 Open Redirect Detected → Redirected to: {final_url}"
        else:
            return False, f"🟢 No Open Redirect → Final URL: {final_url}"
    except requests.exceptions.RequestException as e:
        return False, f"❌ Request Failed: {e}"

def get_server_info(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        return {
            "Content-Type": headers.get("Content-Type", "N/A"),
            "Content-Length": headers.get("Content-Length", "N/A"),
            "Server": headers.get("Server", "N/A"),
            "Status Code": response.status_code
        }
    except requests.exceptions.RequestException as e:
        return {"Error": str(e)}

# ========== Main Script ==========

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("❌ Usage: python openredirect.py https://example.com")
        sys.exit(1)

    url = sys.argv[1]

    print(f"\n🔗 URL Provided: {url}")
    print("🔐 Step 1: Validating URL Security...")

    safe, safety_msg = is_url_safe(url)
    print(f"🔎 Safety Check: {safety_msg}")

    if not safe:
        print("❌ Aborting. URL is unsafe.")
        sys.exit(1)

    print("\n🔁 Step 2: Checking for Open Redirect Vulnerability...")
    found, redirect_msg = test_open_redirect(url)
    print(redirect_msg)

    print("\n🛰️ Step 3: Gathering Server Info...")
    server_info = get_server_info(url)
    for key, value in server_info.items():
        print(f"{key}: {value}")

    print("\n✅ Final Risk Status:")
    if found:
        print("⚠️ Risk: Open Redirect Present. Server behavior should be reviewed.")
    else:
        print("✅ No critical redirect risks detected.")

