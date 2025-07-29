import socket
import sys
from urllib.parse import urlparse

def extract_ip(target):
    try:
        # If it's a URL, parse and extract domain
        parsed = urlparse(target if '://' in target else f'http://{target}')
        hostname = parsed.hostname
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        raise ValueError("❌ Invalid domain or IP.")

def whois_tcp_query(server: str, query: str) -> str:
    with socket.create_connection((server, 43), timeout=10) as s:
        s.sendall((query + "\r\n").encode())
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
    return response.decode(errors='ignore')

def parse_whois_fields(data: str, keys=None):
    if keys is None:
        keys = {
            "inetnum", "netrange", "netname", "descr", "org",
            "org-name", "country", "admin-c", "tech-c",
            "abuse-c", "abuse-mailbox", "status", "mnt-by",
            "mnt-lower", "mnt-routes", "source", "address",
            "cidr", "updated"
        }

    printed = set()
    for line in data.splitlines():
        if ':' not in line:
            continue
        key, val = line.split(':', 1)
        key, val = key.strip().lower(), val.strip()
        if key in keys and (key, val) not in printed:
            print(f"{key.upper():15}: {val}")
            printed.add((key, val))

def whois_lookup_ip(ip: str):
    print(f"\n🔍 WHOIS Lookup for IP: {ip}\n{'='*60}")
    base_data = whois_tcp_query("whois.arin.net", ip)
    if "refer:" in base_data.lower():
        for line in base_data.splitlines():
            if line.lower().startswith("refer:"):
                ref = line.split(":", 1)[1].strip()
                print(f"\n🌐 Referral found: {ref}")
                referral_data = whois_tcp_query(ref, ip)
                print(f"\n📄 WHOIS Record from {ref}\n{'-'*60}")
                parse_whois_fields(referral_data)
                break
    else:
        print(f"\n📄 WHOIS Record from ARIN\n{'-'*60}")
        parse_whois_fields(base_data)

def main():
    if len(sys.argv) != 2:
        print("Usage: python whois.py <domain/IP/URL>")
        sys.exit(1)

    user_input = sys.argv[1]
    try:
        ip = extract_ip(user_input)
        whois_lookup_ip(ip)
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
