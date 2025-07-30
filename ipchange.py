import requests, random, time

API_URL = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt"

def fetch_proxies():
    try:
        r = requests.get(API_URL, timeout=10)
        r.raise_for_status()
        return [line.strip() for line in r.text.splitlines() if line.strip()]
    except Exception as e:
        print("❌ Proxy fetch error:", e)
        return []

def get_ip(proxy):
    try:
        r = requests.get("https://api.ipify.org", proxies={"http": proxy, "https": proxy}, timeout=5)
        return r.text.strip() if r.status_code == 200 else None
    except:
        return None

print("🔍 Fetching live proxies via API...")
proxies = fetch_proxies()
print(f"✅ {len(proxies)} proxies fetched")

if not proxies:
    print("❌ No proxies available. Will retry.")
else:
    print("🌐 Rotating IP every 5 seconds using working proxies...")
    while True:
        proxy = random.choice(proxies)
        ip = get_ip(proxy)
        if ip:
            print(f"[{proxy}] ➜ IP: {ip}")
        else:
            print(f"[{proxy}] ❌ Failed, removing from pool")
            proxies.remove(proxy)
        if not proxies:
            print("🔄 Proxy pool empty—refetching")
            proxies = fetch_proxies()
        time.sleep(5)
