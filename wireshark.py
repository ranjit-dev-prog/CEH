from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict
from tabulate import tabulate
import ipaddress
import re
import os

# Suspicious domain indicators
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "update", "free", "verify", "bonus", "account",
    "banking", "support", "admin", "darkweb", "webmail", "zip", "mov",
    "xn--", "bit.ly", "tinyurl", "t.co", "goo.gl", "@"
]

packet_log = defaultdict(list)

# ---------- SAFETY CHECK ----------
def is_safe_url_or_ip(user_input):
    try:
        ip = ipaddress.ip_address(user_input)
        if ip.is_private or ip.is_loopback or ip.is_multicast:
            print(f"❌ Unsafe IP: {ip}")
            return False
        print(f"✅ Safe IP: {ip}")
        return True
    except ValueError:
        pass

    parsed = urlparse(user_input)
    domain = parsed.netloc if parsed.netloc else parsed.path
    domain = domain.lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in domain:
            print(f"❌ Suspicious keyword in domain: '{keyword}' → {domain}")
            return False

    print(f"✅ Safe Domain: {domain}")
    return True

# ---------- PACKET ANALYSIS ----------
def detect_threats(packet):
    alerts = []
    time_now = datetime.now().strftime("%H:%M:%S")

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "OTHER"
        info = "-"
        length = len(packet)

        if packet.haslayer(TCP):
            proto = "TCP"
            sport, dport = packet[TCP].sport, packet[TCP].dport
            info = f"{sport} → {dport}"
            packet_log[src].append(dport)
            if len(set(packet_log[src])) > 15:
                alerts.append(f"[!] Port Scan Detected from {src}")

        elif packet.haslayer(UDP):
            proto = "UDP"
            sport, dport = packet[UDP].sport, packet[UDP].dport
            info = f"{sport} → {dport}"

        elif packet.haslayer(ICMP):
            proto = "ICMP"
            info = f"Type {packet[ICMP].type}"

        elif packet.haslayer(DNS) and packet.haslayer(DNSQR):
            proto = "DNS"
            query = packet[DNSQR].qname.decode()
            info = f"DNS Query: {query}"
            packet_log[src].append(query)
            if len(set(packet_log[src])) > 10 and len(query) > 25:
                alerts.append(f"[!] DNS Exfiltration? {src} queried many long domains")

        row = [[time_now, proto, src, dst, info, str(length)]]
        print(tabulate(row, headers=["Time", "Proto", "Source IP", "Destination", "Info", "Length"], tablefmt="fancy_grid"))

        for alert in alerts:
            print(f"⚠️ {alert}")

# ---------- MAIN ----------
def main():
    os.system("cls" if os.name == "nt" else "clear")
    print("🐺 WolfSniff-X: Network Sniffer + Keyword-Based Safety Checker")
    print("--------------------------------------------------------------")
    user_input = input("🌐 Enter URL or IP to analyze: ").strip()

    if not is_safe_url_or_ip(user_input):
        print("🚫 Unsafe input. Sniffing aborted.")
        return

    print("\n📶 Sniffing started... Showing real-time traffic:\n")
    print("┏━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┓")
    sniff(prn=detect_threats, store=False)

if __name__ == "__main__":
    main()
