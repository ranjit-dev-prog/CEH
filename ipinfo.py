import argparse
import socket
import requests
import ipaddress
from ipwhois import IPWhois

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

def geolocation_info(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        print("\n🌍 Geolocation Info:")
        lat, lon = res.get('lat'), res.get('lon')
        for key in ['query', 'country', 'regionName', 'city', 'isp', 'org', 'as', 'lat', 'lon']:
            print(f"  {key.capitalize()}: {res.get(key)}")
        if lat and lon:
            map_link = f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"
            print(f"\n🗺️  View on Map: {map_link}")
    except:
        print("❌ Error retrieving geolocation.")

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
        print("❌ WHOIS failed:", e)

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
    parser = argparse.ArgumentParser(description="🔍 IP Information Finder")
    parser.add_argument("ip", help="IP address to analyze")
    args = parser.parse_args()
    
    ip = args.ip
    if not validate_ip(ip):
        return

    geolocation_info(ip)
    whois_info(ip)
    reverse_dns(ip)
    blacklist_check(ip)

if __name__ == "__main__":
    main()
