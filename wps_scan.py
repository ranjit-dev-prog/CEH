import subprocess
import socket
import re
import requests
import argparse
from mac_vendor_lookup import MacLookup


def get_wifi_details():
    try:
        result = subprocess.check_output("netsh wlan show interfaces", shell=True, text=True)
        bssid = re.search(r'BSSID\s*:\s*(.*)', result)
        ssid = re.search(r'SSID\s*:\s*(.*)', result)
        signal = re.search(r'Signal\s*:\s*(.*)', result)
        channel = re.search(r'Channel\s*:\s*(.*)', result)
        radio_type = re.search(r'Radio type\s*:\s*(.*)', result)

        return {
            "BSSID": bssid.group(1).strip() if bssid else "N/A",
            "SSID": ssid.group(1).strip() if ssid else "N/A",
            "Signal Strength": signal.group(1).strip() if signal else "N/A",
            "Channel": channel.group(1).strip() if channel else "N/A",
            "Radio Type": radio_type.group(1).strip() if radio_type else "N/A"
        }
    except Exception as e:
        return {"Error": f"Failed to get Wi-Fi details: {str(e)}"}


def get_vendor(mac):
    try:
        return MacLookup().lookup(mac)
    except:
        return "Unknown Vendor"


def scan_ports(ip):
    open_ports = []
    for port in range(1, 1025):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        except:
            continue
    return open_ports


def resolve_dns(ip):
    try:
        host = socket.gethostbyaddr(ip)
        return host[0]
    except socket.herror:
        return "DNS Not Resolved"


def check_http_response(ip):
    try:
        url = f"http://{ip}"
        response = requests.get(url, timeout=3)
        return {
            "Status Code": response.status_code,
            "Server": response.headers.get("Server", "Unknown"),
            "Content-Type": response.headers.get("Content-Type", "Unknown"),
            "Content-Length": response.headers.get("Content-Length", "Unknown")
        }
    except Exception as e:
        return {"Error": f"HTTP Request Failed: {str(e)}"}


def wps_check_placeholder():
    print("[!] WPS Vulnerability Scan: Feature not implemented (requires external tools like Reaver)")


def main():
    parser = argparse.ArgumentParser(description="Wi-Fi Access Point Scanner")
    parser.add_argument("ip", help="IP address of the access point")
    args = parser.parse_args()
    ip = args.ip

    print("\n[*] Gathering Wireless Info...\n")
    wifi_info = get_wifi_details()
    bssid = wifi_info.get("BSSID", "N/A")
    vendor = get_vendor(bssid) if bssid != "N/A" else "Unknown"

    print(f"SSID: {wifi_info.get('SSID')}")
    print(f"BSSID (MAC): {bssid}")
    print(f"Vendor: {vendor}")
    print(f"Signal Strength: {wifi_info.get('Signal Strength')}")
    print(f"Channel: {wifi_info.get('Channel')}")
    print(f"Radio Type: {wifi_info.get('Radio Type')}")

    print("\n[*] Resolving DNS for IP:", ip)
    dns_name = resolve_dns(ip)
    print("Resolved DNS Name:", dns_name)

    print("\n[*] Scanning open ports (top 1024) on:", ip)
    open_ports = scan_ports(ip)
    print("Open Ports:", open_ports if open_ports else "None Found")

    print("\n[*] HTTP Headers Check:")
    http_info = check_http_response(ip)
    for key, value in http_info.items():
        print(f"{key}: {value}")

    print("\n[*] WPS Check (Basic):")
    if "WPS" in wifi_info.get("Radio Type", ""):
        print("Possible WPS Support Detected")
    else:
        print("WPS Info Not Detected from Windows Interface")

    wps_check_placeholder()


if __name__ == "__main__":
    main()
