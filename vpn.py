import os
import random
import tkinter as tk
import requests
import winreg
import threading
import time

# =============================
# Proxy Functions
# =============================
def fetch_proxies():
    """Fetch fresh proxy list from API"""
    try:
        url = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=3000&country=all"
        response = requests.get(url, timeout=10)
        proxies = response.text.splitlines()
        print(f"[DEBUG] Fetched {len(proxies)} proxies")
        return proxies if proxies else []
    except Exception as e:
        print("[ERROR] Could not fetch proxies:", e)
        return []


def set_system_proxy(proxy):
    """Enable Windows system proxy"""
    internet_settings = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0, winreg.KEY_SET_VALUE,
    )
    winreg.SetValueEx(internet_settings, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    winreg.SetValueEx(internet_settings, "ProxyServer", 0, winreg.REG_SZ, proxy)
    winreg.CloseKey(internet_settings)
    os.system("ipconfig /flushdns")


def disable_system_proxy():
    """Disable Windows system proxy"""
    internet_settings = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0, winreg.KEY_SET_VALUE,
    )
    winreg.SetValueEx(internet_settings, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    winreg.CloseKey(internet_settings)
    os.system("ipconfig /flushdns")


def get_ip(proxy=None):
    """Check current IP address"""
    try:
        proxies = {"http": proxy, "https": proxy} if proxy else None
        res = requests.get("https://httpbin.org/ip", proxies=proxies, timeout=10)
        return res.json().get("origin", "N/A")
    except Exception as e:
        return f"Error: {e}"


# =============================
# GUI App
# =============================
class VPNApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Proxy VPN")
        self.root.geometry("450x300")
        self.root.resizable(False, False)

        self.proxies = []
        self.current_proxy = None
        self.auto_rotate = False
        self.rotate_interval = 60  # seconds (change as needed)

        self.status_label = tk.Label(root, text="Status: Disconnected", fg="red", font=("Arial", 12))
        self.status_label.pack(pady=20)

        tk.Button(root, text="Connect", width=25, command=self.connect).pack(pady=5)
        tk.Button(root, text="Rotate IP", width=25, command=self.rotate).pack(pady=5)
        tk.Button(root, text="Disconnect", width=25, command=self.disconnect).pack(pady=5)
        tk.Button(root, text="Start Auto-Rotate", width=25, command=self.start_auto_rotate).pack(pady=5)
        tk.Button(root, text="Stop Auto-Rotate", width=25, command=self.stop_auto_rotate).pack(pady=5)

        self.ip_label = tk.Label(root, text="Your IP: N/A", fg="blue", font=("Arial", 10))
        self.ip_label.pack(pady=20)

    def connect(self):
        if not self.proxies:
            self.proxies = fetch_proxies()
        if not self.proxies:
            self.status_label.config(text="No proxies available ❌", fg="red")
            return

        self.current_proxy = random.choice(self.proxies)
        set_system_proxy(self.current_proxy)

        ip = get_ip(self.current_proxy)
        if "Error" not in ip:
            self.status_label.config(text="Connected ✅", fg="green")
        else:
            self.status_label.config(text="Connection Failed ❌", fg="red")
        self.ip_label.config(text=f"Your IP: {ip}")

    def rotate(self):
        if not self.proxies:
            self.proxies = fetch_proxies()
        if not self.proxies:
            self.ip_label.config(text="No proxies available ❌")
            return

        self.current_proxy = random.choice(self.proxies)
        set_system_proxy(self.current_proxy)

        ip = get_ip(self.current_proxy)
        self.ip_label.config(text=f"Your IP: {ip}")

    def disconnect(self):
        disable_system_proxy()
        self.status_label.config(text="Disconnected ❌", fg="red")
        self.ip_label.config(text="Your IP: N/A")
        self.auto_rotate = False

    def start_auto_rotate(self):
        self.auto_rotate = True
        self.status_label.config(text="Auto-Rotate ON 🔄", fg="orange")
        threading.Thread(target=self.auto_rotate_worker, daemon=True).start()

    def stop_auto_rotate(self):
        self.auto_rotate = False
        self.status_label.config(text="Auto-Rotate OFF ⏹️", fg="red")

    def auto_rotate_worker(self):
        while self.auto_rotate:
            self.rotate()
            time.sleep(self.rotate_interval)


if __name__ == "__main__":
    root = tk.Tk()
    app = VPNApp(root)
    root.mainloop()
