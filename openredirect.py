import requests
import socket
import ssl
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
            return True, f"✅ SSL Cert Valid: {cert['notAfter']}"
    except Exception as e:
        return False, f"❌ SSL Check Failed: {e}"

def has_suspicious_keywords(url):
    keywords = ['login', 'secure', 'verify', 'update', 'bonus', 'win', 'bank', 'free', 'signin', 'paypal']
    return any(k in url.lower() for k in keywords)

def is_ip_address(domain):
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False

def is_url_safe_advanced(url):
    parsed = urlparse(url)

    if parsed.scheme != 'https':
        return False, "❌ URL does not use HTTPS"

    if is_ip_address(parsed.hostname):
        return False, "❌ URL uses IP address instead of domain"

    if has_suspicious_keywords(url):
        return False, "⚠️ Suspicious keywords found in URL"

    valid_cert, cert_message = is_valid_https_cert(parsed.hostname)
    if not valid_cert:
        return False, cert_message

    return True, "✅ URL is safe"

def test_open_redirect(base_url, test_payload="/?next=https://evil.com"):
    target_url = urljoin(base_url, test_payload)

    try:
        response = requests.get(target_url, allow_redirects=True, timeout=10)
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
            "Connection": headers.get("Connection", "N/A"),
            "Cache-Control": headers.get("Cache-Control", "N/A"),
            "Server": headers.get("Server", "N/A"),
            "Status Code": response.status_code
        }
    except requests.exceptions.RequestException as e:
        return {"Error": str(e)}

# ========== MAIN EXECUTION ==========
if __name__ == "__main__":
    url = input("🔗 Enter the base URL (must be HTTPS): ").strip()

    print("\n🔐 Checking URL Safety...")
    safe, message = is_url_safe_advanced(url)
    print(f"Safety Check: {message}")

    if not safe:
        print("❌ Aborting test. Unsafe URL.")
    else:
        print("\n🔍 Testing for Open Redirect...")
        redirect_found, redirect_msg = test_open_redirect(url)
        print(f"Redirect Test: {redirect_msg}")

        print("\n📡 Gathering Server Info...")
        info = get_server_info(url)
        for k, v in info.items():
            print(f"{k}: {v}")
