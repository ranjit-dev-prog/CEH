import socket
import sys
from urllib.parse import urlparse

def resolve_ip(input_value):
    """
    Resolves the IP address from a domain or direct IP input.
    Accepts URLs, domains, or raw IPs.
    """
    try:
        # If input looks like a URL, parse it
        parsed = urlparse(input_value)
        hostname = parsed.hostname if parsed.hostname else input_value
    except:
        hostname = input_value

    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        raise Exception(f"❌ Could not resolve hostname: {hostname}")

def fetch_asn_info(ip_address):
    """
    Connects to whois.cymru.com to perform ASN lookup for the IP.
    Uses the 'verbose' mode to get detailed ASN data.
    """
    try:
        # Format the query for Team Cymru WHOIS service
        query = f"begin\nverbose\n{ip_address}\nend\n"

        with socket.create_connection(("whois.cymru.com", 43), timeout=10) as sock:
            sock.sendall(query.encode())
            raw_response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw_response += chunk

        decoded = raw_response.decode().strip().splitlines()

        # Remove comments (lines starting with '#')
        data_lines = [line for line in decoded if not line.startswith("#")]

        if len(data_lines) < 2:
            raise Exception("⚠️ No ASN data found for the IP address.")

        headers = [h.strip().lower() for h in data_lines[0].split("|")]
        values = [v.strip() for v in data_lines[1].split("|")]
        asn_data = dict(zip(headers, values))

        return asn_data

    except Exception as e:
        raise Exception(f"❌ ASN Lookup Error: {e}")

def print_asn_report(asn_data, ip_address):
    """
    Nicely formats and prints ASN data to the terminal.
    """
    print("\n📡 ASN Lookup Report")
    print("=" * 60)
    print(f"{'Resolved IP':20}: {ip_address}")
    print(f"{'ASN Number':20}: {asn_data.get('asn', 'N/A')}")
    print(f"{'BGP Prefix':20}: {asn_data.get('bgp prefix', 'N/A')}")
    print(f"{'Country Code':20}: {asn_data.get('cc', 'N/A')}")
    print(f"{'Registry':20}: {asn_data.get('registry', 'N/A')}")
    print(f"{'Allocated Date':20}: {asn_data.get('allocated', 'N/A')}")
    print(f"{'ASN Name':20}: {asn_data.get('as name', 'N/A')}")
    print(f"{'Full Record':20}: {asn_data}")
    print("=" * 60)

def main():
    """
    Main function: Handles command-line input and runs the lookup.
    Usage: python asnlookup.py <domain or IP>
    """
    if len(sys.argv) != 2:
        print("❗ Usage: python asnlookup.py <domain or IP>")
        print("    Example: python asnlookup.py google.com")
        return

    user_input = sys.argv[1]

    try:
        ip_address = resolve_ip(user_input)
        asn_info = fetch_asn_info(ip_address)
        print_asn_report(asn_info, ip_address)

    except Exception as err:
        print(f"[ERROR] {err}")

if __name__ == "__main__":
    main()
