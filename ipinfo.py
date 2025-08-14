import argparse
import socket
import ipaddress
from ipwhois import IPWhois
from urllib.parse import urlparse

def get_ip_from_url(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname if parsed.hostname else url
        ip = socket.gethostbyname(hostname)
        print(f"🔗 URL: {url}")
        print(f"🌐 Hostname: {hostname}")
        print(f"🔢 IP Address: {ip}")
        return ip
    except Exception as e:
        print(f"❌ Could not resolve IP from URL: {e}")
        return None

def validate_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        print(f"✅ Valid IP: {ip}")
        print(f"🌐 IP Version: {ip_obj.version}")
        print(f"🏠 Private IP: {ip_obj.is_private}")
        return True
    except ValueError:
        print("❌ Invalid IP address!")
        return False

def whois_info(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        print("\n🔍 WHOIS Info:")
        print(f"  ASN: {res.get('asn')}")
        print(f"  Org: {res.get('network', {}).get('name')}")
        print(f"  Country: {res.get('asn_country_code')}")
        print(f"  Email(s): {res.get('network', {}).get('abuse_emails')}")
    except Exception as e:
        print("❌ WHOIS info failed. Reason:", e)
        print("ℹ️  WHOIS info may not be available for this IP. due to private ip and security issue Continuing...\n")

def reverse_dns(ip):
    try:
        host = socket.gethostbyaddr(ip)
        print(f"\n🔁 Reverse DNS: {host[0]}")
    except:
        print("❌ Reverse DNS not found.")

def blacklist_check(ip):
    try:
        dnsbl_list = [
            "zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net"
        ]
        print("\n🚫 Blacklist Check:")
        for bl in dnsbl_list:
            try:
                query = '.'.join(reversed(ip.split("."))) + "." + bl
                socket.gethostbyname(query)
                print(f"  ❌ Listed on {bl}")
            except:
                print(f"  ✅ Not listed on {bl}")
    except Exception as e:
        print("❌ Error checking blacklists:", e)

def main():
    parser = argparse.ArgumentParser(description="🔍 IP/URL Information Finder (No API)")
    parser.add_argument("target", help="IP address or URL to analyze")
    args = parser.parse_args()
    
    target = args.target
    # Check if input is an IP address
    try:
        ipaddress.ip_address(target)
        ip = target
    except ValueError:
        ip = get_ip_from_url(target)
        if not ip:
            return

    if not validate_ip(ip):
        return

    whois_info(ip)
    reverse_dns(ip)
    blacklist_check(ip)

if __name__ == "__main__":
    main()
