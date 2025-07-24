import socket
from urllib.parse import urlparse

def extract_ip_from_https(url):
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        raise ValueError("❌ Only HTTPS URLs allowed.")
    return socket.gethostbyname(parsed.hostname)

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
        # Common WHOIS fields
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
    try:
        url = input("Enter HTTPS URL: ").strip()
        ip = extract_ip_from_https(url)
        whois_lookup_ip(ip)
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
