import argparse
import requests
from bs4 import BeautifulSoup
from collections import Counter
import docx
import re
import os
import heapq

PHISHING_TERMS = {"verify", "account", "login", "password", "reset", "security", "update", "billing", "session", "urgent"}
BRAND_NAMES = {"facebook", "instagram", "microsoft", "google", "linkedin", "twitter", "amazon"}

# Trie for prefix search
class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end = False

class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, word):
        node = self.root
        for ch in word:
            node = node.children.setdefault(ch, TrieNode())
        node.is_end = True

    def starts_with(self, prefix):
        node = self.root
        for ch in prefix:
            if ch not in node.children:
                return []
            node = node.children[ch]
        return self._collect_words(node, prefix)

    def _collect_words(self, node, prefix):
        words = []
        if node.is_end:
            words.append(prefix)
        for ch, child in node.children.items():
            words.extend(self._collect_words(child, prefix + ch))
        return words

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
    freq = Counter(words)
    heap = []
    for word, count in freq.items():
        if word in BRAND_NAMES:
            continue
        heapq.heappush(heap, (-count, word))  # Max-heap behavior
    return heap

def keyword_explorer(source, prefix=None):
    if os.path.exists(source):
        content = read_text_from_file(source)
    else:
        content = fetch_text_from_url(source)
    if not content:
        print("[⚠️] No content found.")
        return

    print(f"\n✅ Content scanned. Extracting keywords...")
    scored_keywords = score_keywords(content)

    trie = Trie()
    top_keywords = []
    for _ in range(min(500, len(scored_keywords))):
        count, word = heapq.heappop(scored_keywords)
        trie.insert(word)
        top_keywords.append((word, -count))

    if prefix:
        print(f"\n🔍 Filtering keywords with prefix: '{prefix}'\n")
        matched = trie.starts_with(prefix)
        for i, word in enumerate(matched, 1):
            print(f"{i:03}. {word}")
    else:
        print(f"\n🔑 Top Keywords:\n")
        for i, (kw, freq) in enumerate(top_keywords, 1):
            marker = "⚠️" if kw in PHISHING_TERMS else ""
            print(f"{i:03}. {kw:<20} | Freq: {freq} {marker}")

    flagged = [kw for kw, _ in top_keywords if kw in PHISHING_TERMS]
    if flagged:
        print(f"\n🛑 Phishing Indicators Found: {', '.join(flagged)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Keyword Generator with DSA")
    parser.add_argument("source", help="URL or path to .txt/.docx file")
    parser.add_argument("--prefix", help="Prefix to filter keywords", default=None)
    args = parser.parse_args()

    keyword_explorer(args.source, args.prefix)
