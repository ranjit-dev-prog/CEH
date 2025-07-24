import socket
import dns.resolver
import dns.reversename
import ssl
from urllib.parse import urlparse
import requests

def check_url_safety(url):
    try:
        response = requests.get(url, timeout=5, verify=True)
        cert = ssl.get_server_certificate((urlparse(url).hostname, 443))
        print("✅ URL is safe and certificate is present.\n")
        return True
    except Exception as e:
        print(f"❌ URL safety check failed: {e}\n")
        return False

def get_ip_from_url(url):
    try:
        domain = urlparse(url).hostname or url
        ip = socket.gethostbyname(domain)
        return domain, ip
    except socket.gaierror:
        print("❌ Could not resolve IP.")
        return None, None

def reverse_dns_lookup(ip):
    try:
        rev_name = dns.reversename.from_address(ip)
        ptr_record = dns.resolver.resolve(rev_name, "PTR")
        return str(ptr_record[0])
    except Exception:
        return "PTR Record Not Found"

def resolve_dns(domain):
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    print("🔍 DNS Records:\n")
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for ans in answers:
                print(f"📄 Type: {rtype}")
                print(f"🌐 Domain: {domain}")
                if rtype in ["A", "AAAA"]:
                    print(f"🔢 IP: {ans.to_text()}")
                elif rtype == "MX":
                    print(f"📮 Mail Exchanger: {ans.exchange} (Priority {ans.preference})")
                elif rtype == "CNAME":
                    print(f"🔁 Alias: {ans.target}")
                elif rtype == "TXT":
                    print(f"📝 Text: {ans.to_text()}")
                elif rtype == "NS":
                    print(f"🛰️ Nameserver: {ans.target}")
                elif rtype == "SOA":
                    print(f"📋 Primary NS: {ans.mname}")
                    print(f"📧 Responsible Email: {ans.rname}")
                print(f"⏱️ TTL: {answers.rrset.ttl}\n")
        except Exception:
            print(f"❌ No {rtype} records found for {domain}\n")

def dns_info_tool(input_value):
    print(f"\n🔐 Checking input: {input_value}")
    
    # Check if it's an IP address
    try:
        socket.inet_aton(input_value)
        ip = input_value
        domain = reverse_dns_lookup(ip)
        print(f"\n🔁 Reverse DNS (PTR): {domain}")
        print(f"🔢 IP: {ip}")
        resolve_dns(domain)
        return
    except socket.error:
        pass

    # Treat as URL/domain
    if not input_value.startswith("http"):
        input_value = "http://" + input_value

    if check_url_safety(input_value):
        domain, ip = get_ip_from_url(input_value)
        if domain and ip:
            print(f"✅ Domain: {domain}")
            print(f"🔢 IP: {ip}")
            print(f"🔁 PTR Record: {reverse_dns_lookup(ip)}")
            resolve_dns(domain)

# 🔧 Test it here
if __name__ == "__main__":
    user_input = input("Enter URL or IP: ")
    dns_info_tool(user_input)
