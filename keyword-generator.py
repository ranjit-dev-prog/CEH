import requests
from bs4 import BeautifulSoup
from collections import Counter, defaultdict
import docx
import re
import os

PHISHING_TERMS = {"verify", "account", "login", "password", "reset", "security", "update", "billing", "session", "urgent"}
BRAND_NAMES = {"facebook", "instagram", "microsoft", "google", "linkedin", "twitter", "amazon"}

def fetch_text_from_url(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=8)
        soup = BeautifulSoup(response.text, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        return soup.get_text(separator=' ', strip=True)
    except Exception as e:
        print(f"[ERROR] Could not fetch URL: {e}")
        return ""

def read_text_from_file(file_path):
    text = ""
    try:
        if file_path.endswith(".txt"):
            with open(file_path, "r", encoding="utf-8") as f:
                text = f.read()
        elif file_path.endswith(".docx"):
            doc = docx.Document(file_path)
            text = " ".join(p.text for p in doc.paragraphs)
        else:
            print("[⚠️] Unsupported file type. Use .txt or .docx.")
    except Exception as e:
        print(f"[ERROR] Could not read file: {e}")
    return text

def score_keywords(text, min_length=4):
    text = text.lower()
    words = re.findall(r'\b[a-z][a-z0-9]{%d,}\b' % min_length, text)
    positions = {word: i for i, word in enumerate(words)}
    freq = Counter(words)
    scored = []
    for word, count in freq.items():
        if word in BRAND_NAMES:
            continue
        pos_score = 1 - (positions[word] / len(words))
        score = round((count * 0.7 + pos_score * 0.3), 4)
        scored.append((word, score))
    return sorted(scored, key=lambda x: x[1], reverse=True)[:500]

def highlight_phishing_terms(keywords):
    flagged = [kw for kw, _ in keywords if kw in PHISHING_TERMS]
    return flagged

def keyword_explorer(source):
    if os.path.exists(source):
        content = read_text_from_file(source)
    else:
        content = fetch_text_from_url(source)
    if not content:
        print("[⚠️] No content found.")
        return

    print(f"\n✅ Content scanned. Extracting and scoring keywords...\n")
    top_keywords = score_keywords(content)
    phishing_hits = highlight_phishing_terms(top_keywords)

    print(f"🔑 Top {len(top_keywords)} Keywords:\n")
    for i, (kw, score) in enumerate(top_keywords, 1):
        marker = "⚠️" if kw in PHISHING_TERMS else ""
        print(f"{i:03}. {kw:<20} | Score: {score:.4f} {marker}")

    if phishing_hits:
        print(f"\n🛑 Phishing Indicators Found: {', '.join(phishing_hits)}")

# 🎯 Usage (CLI-style)
if __name__ == "__main__":
    source_input = input("📥 Enter a URL or path to .txt/.docx file: ").strip()
    keyword_explorer(source_input)