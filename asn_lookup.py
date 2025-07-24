import socket
import urllib.parse
import urllib.request
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

def unshorten_url(url):
    try:
        return urllib.request.urlopen(url).geturl()
    except Exception as e:
        print(f"❌ Failed to unshorten URL: {e}")
        return None

def is_shortened_url(url):
    shortened_domains = [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly",
        "adf.ly", "bit.do", "cutt.ly", "is.gd", "shorte.st", "trib.al"
    ]
    domain = urllib.parse.urlparse(url).netloc
    return domain in shortened_domains

def extract_ip_from_url(url):
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.netloc or parsed.path  # path for input like just 'example.com'
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception as e:
        print(f"❌ Domain resolution failed: {e}")
        return None

def get_asn_info(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        asn = res.get("asn")
        asn_description = res.get("asn_description")
        cidr = res.get("network", {}).get("cidr")
        print(f"🔎 ASN Info for {ip}")
        print(f"   ASN Number     : {asn}")
        print(f"   ASN Name       : {asn_description}")
        print(f"   CIDR Range     : {cidr}")
    except IPDefinedError:
        print("❌ Reserved IP address (like private/local). No ASN info.")
    except Exception as e:
        print(f"❌ Failed to fetch ASN info: {e}")

def main():
    user_input = input("🔐 Enter IP address or URL: ").strip()

    # Unshorten URL if needed
    if "http" in user_input:
        if is_shortened_url(user_input):
            print("⚠️ Detected a shortened URL. Attempting to unshorten...")
            unshortened = unshorten_url(user_input)
            if not unshortened:
                print("❌ Unable to resolve masked URL. Exiting.")
                return
            user_input = unshortened
            print(f"🔗 Unshortened to: {user_input}")

        ip = extract_ip_from_url(user_input)
        if not ip:
            print("❌ Could not resolve IP. Exiting.")
            return
    else:
        ip = user_input  # assume it's already an IP

    # Now get ASN details
    get_asn_info(ip)

if __name__ == "__main__":
    main()
