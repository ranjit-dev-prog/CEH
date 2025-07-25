import re
import requests
from urllib.parse import urlparse, urlunparse

SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "rebrand.ly", "ow.ly",
    "buff.ly", "shorturl.at", "adf.ly", "linktr.ee", "is.gd"
}

def sanitize_input(url):
    url = url.strip()
    pattern = re.compile(r'^(https?://)?[\w.-]+\.[a-z]{2,}(/.*)?$', re.IGNORECASE)
    if not pattern.match(url):
        raise ValueError("Invalid URL format")
    if not urlparse(url).scheme:
        url = "https://" + url  # Force HTTPS
    return url

def is_safe_url(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host.lower() in SHORTENERS:
        return False, "Masked or shortened"
    if parsed.scheme != "https":
        return False, "Must use HTTPS"
    return True, "OK"

def link_exists(url, timeout=5):
    try:
        resp = requests.head(url, allow_redirects=True, timeout=timeout)
        return resp.status_code < 400
    except requests.RequestException:
        return False

def remove_query_params(url):
    parsed = urlparse(url)
    clean = parsed._replace(query='', fragment='')
    return urlunparse(clean)

def process_user_url(url):
    try:
        url = sanitize_input(url)
        safe, reason = is_safe_url(url)
        if not safe:
            return f"[❌] Blocked → {reason}: {url}"
        if not link_exists(url):
            return f"[🚫] Dead link → {url}"
        trimmed = remove_query_params(url)
        return f"[✅] Cleaned → {trimmed}"
    except Exception as e:
        return f"[⚠️] Error → {e}: {url}"

# 📎 Try it
user_input = input("Enter a URL: ").strip()
print(process_user_url(user_input))