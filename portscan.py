import socket
import threading
import sys
import ssl
from urllib.parse import urlparse
import re

open_ports = []
lock = threading.Lock()

# 1. Check if input is an IP address
def is_ip_address(domain):
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False

# 2. Check suspicious keywords
def has_suspicious_keywords(url):
    keywords = ['login', 'secure', 'verify', 'update', 'bonus', 'win', 'bank', 'signin', 'paypal']
    return any(k in url.lower() for k in keywords)

# 3. Check SSL certificate
def is_valid_https_cert(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            if not cert:
                return False, "❌ No SSL certificate found"
            return True, f"✅ SSL Cert Valid (Expires: {cert['notAfter']})"
    except Exception as e:
        return False, f"❌ SSL Check Failed: {e}"

# 4. Check overall safety
def is_url_safe(url):
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path  # handles IPs and plain domains

    if parsed.scheme != 'https':
        return False, "❌ URL does not use HTTPS"

    if is_ip_address(domain):
        return False, "❌ IP-based URL — not recommended"

    if has_suspicious_keywords(url):
        return False, "⚠️ Suspicious keywords found in URL"

    valid_cert, cert_msg = is_valid_https_cert(domain)
    if not valid_cert:
        return False, cert_msg

    return True, "✅ URL passed basic safety checks"

# 5. Port Scanner
def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        result = sock.connect_ex((target, port))
        if result == 0:
            with lock:
                print(f"🔓 Port {port} is OPEN")
                open_ports.append(port)
        sock.close()
    except:
        pass

def scan_ports(target, start_port=1, end_port=1024):
    print(f"\n🔍 Scanning {target} from port {start_port} to {end_port}...")
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"❌ Could not resolve target: {target}")
        return

    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(target_ip, port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    if not open_ports:
        print("✅ No open ports found.")
    else:
        open_ports.sort()
        print(f"\n✅ Open Ports: {open_ports}")

# 6. Main Execution
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python portscanner.py https://example.com")
        sys.exit(1)

    input_url = sys.argv[1]
    parsed = urlparse(input_url)
    target = parsed.netloc if parsed.netloc else parsed.path

    print(f"🔐 Checking URL safety for: {target}")
    safe, message = is_url_safe(input_url)
    print(f"🛡️ Safety Check: {message}")

    if not safe:
        print("❌ Aborting scan due to safety concerns.")
        sys.exit(1)

    scan_ports(target)
