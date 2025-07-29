import cv2
import validators
import os

# 🛡️ List of suspicious indicators
SUSPICIOUS_KEYWORDS = [
    "bit.ly", "tinyurl", "grabify", "shorturl", "phish", "scam", "redirect", "free", "verify", 
    "login", "password", "update", "dropbox", "malware", "payload", "virus", "exe", ".apk", ".bat", ".js"
]

def is_url_suspicious(url):
    url = url.lower()
    return any(keyword in url for keyword in SUSPICIOUS_KEYWORDS)

def generate_risk_statement(data, is_url, is_suspicious):
    if not is_url:
        return {
            "verdict": "⚠️ NON-URL CONTENT",
            "risk": "Could be a command, script, or payload.",
            "suggestion": "Avoid executing or copying unless you trust the source."
        }

    if is_suspicious:
        return {
            "verdict": "⚠️ POTENTIALLY MALICIOUS URL",
            "risk": "This link contains known redirection or phishing patterns.",
            "suggestion": "Do not click. Use VirusTotal or Google Safe Browsing to scan it."
        }

    return {
        "verdict": "✅ SAFE (No suspicious patterns detected)",
        "risk": "Basic keyword and format checks passed.",
        "suggestion": "Still verify with a real-time scanning tool if unsure."
    }

def analyze_qr_image(image_path):
    if not os.path.exists(image_path):
        print(f"[!] Error: File not found - {image_path}")
        return

    img = cv2.imread(image_path)
    detector = cv2.QRCodeDetector()
    data, bbox, _ = detector.detectAndDecode(img)

    if not data:
        print("[!] No QR Code detected.")
        return

    print(f"\n[+] QR Code Content Detected:\n{data}")

    is_url = validators.url(data)
    is_suspicious = is_url_suspicious(data) if is_url else False

    report = generate_risk_statement(data, is_url, is_suspicious)

    print("\n=== RISK REPORT ===")
    print(f"VERDICT    : {report['verdict']}")
    print(f"RISK LEVEL : {report['risk']}")
    print(f"SUGGESTION : {report['suggestion']}")
    print("===================")

def main():
    print("== QR CODE MALWARE & URL SCANNER ==")
    img_path = input("Enter path to QR code image: ").strip()
    analyze_qr_image(img_path)

if __name__ == "__main__":
    main()
