import subprocess
import socket
import re
import requests
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
        vendor = MacLookup().lookup(mac)
        return vendor
    except:
        return "Unknown Vendor"

def scan_ports(ip):
    open_ports = []
    for port in range(1, 1025):  # Top 1024 ports
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def main():
    ip = input("Enter IP address of the access point (e.g., 192.168.1.1): ")

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

    print("\n[*] Scanning open ports (top 1024) on IP:", ip)
    open_ports = scan_ports(ip)
    print("Open Ports:", open_ports if open_ports else "No open ports found")

    print("\n[*] WPS Information (Limited on Windows):")
    if "WPS" in wifi_info.get("Radio Type", ""):
        print("WPS may be supported (based on radio type).")
    else:
        print("No WPS info available on Windows through this method.")

if __name__ == "__main__":
    main()
