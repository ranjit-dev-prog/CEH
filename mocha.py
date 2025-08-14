import requests
import validators
import json
import time
import urllib.parse
import sys

# Suspicious keywords list
SUSPICIOUS_KEYWORDS = [
    "bit.ly", "tinyurl", "grabify", "shorturl", "phish", "scam", "redirect",
    "free", "verify", "login", "password", "update", "dropbox", "malware", "payload",
    "virus", ".exe", ".apk", ".bat", ".js"
]

def is_suspicious(url):
    return any(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS)

def is_masked(url):
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc != url.replace(parsed.scheme + "://", "").split("/")[0]

def is_reachable(url):
    try:
        res = requests.head(url, timeout=5, allow_redirects=True)
        return res.status_code < 400
    except:
        return False

def get_api_details(url, method, headers, body):
    try:
        method = method.upper()
        start_time = time.time()

        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=body, timeout=10)
        elif method == "PUT":
            response = requests.put(url, headers=headers, json=body, timeout=10)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, timeout=10)
        else:
            return {"error": "Invalid method"}

        duration = int((time.time() - start_time) * 1000)
        try:
            json_data = response.json()
        except:
            json_data = response.text[:200]

        return {
            "method": method,
            "status_code": response.status_code,
            "status_text": response.reason,
            "response_time_ms": duration,
            "headers": dict(response.headers),
            "response_body_preview": json_data[:2] if isinstance(json_data, list) else json_data,
            "total_results": len(json_data) if isinstance(json_data, list) else 1,
            "content_type": response.headers.get("Content-Type", "unknown"),
            "assertions": {
                "status_expected": 200,
                "passed": response.status_code == 200,
                "body_must_contain": "userId",
                "body_passed": "userId" in str(json_data)
            }
        }

    except Exception as e:
        return {"error": str(e)}

# ---- RUN ----
if __name__ == "__main__":
    # Check for command-line arguments
    if len(sys.argv) > 1:
        url = sys.argv[1].strip()
        method = sys.argv[2].strip().upper() if len(sys.argv) > 2 else "GET"
        headers = {}
        body = {}
    else:
        url = input("🔗 Enter API URL to test: ").strip()
        method = input("📥 HTTP Method (GET/POST/PUT/DELETE): ").strip().upper()
        headers_input = input("🧾 Add headers as JSON (or leave blank for none): ").strip()
        if headers_input:
            try:
                headers = json.loads(headers_input)
            except json.JSONDecodeError as e:
                print(f"❌ Invalid header JSON: {e}. Using empty headers.")
                headers = {}
        else:
            headers = {}

        body_input = input("📝 Add JSON body (for POST/PUT, or leave blank): ").strip()
        if body_input:
            try:
                body = json.loads(body_input)
            except json.JSONDecodeError as e:
                print(f"❌ Invalid body JSON: {e}. Using empty body.")
                body = {}
        else:
            body = {}

    result = {
        "url": url,
        "valid_format": validators.url(url),
        "suspicious": is_suspicious(url),
        "masked": is_masked(url),
        "reachable": is_reachable(url),
        "safe_for_api_test": False
    }

    if result["valid_format"] and not result["suspicious"] and not result["masked"] and result["reachable"]:
        result["safe_for_api_test"] = True
        result["api_test"] = get_api_details(url, method, headers, body)
    else:
        result["reason"] = "URL is not safe for API testing."

    print(json.dumps(result, indent=2))