import argparse
import requests
from bs4 import BeautifulSoup
from collections import Counter
import docx
import re
import os
import heapq
import nltk
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer

nltk.download('stopwords')
STOPWORDS = set(stopwords.words("english"))
STEMMER = PorterStemmer()

PHISHING_TERMS = {"verify", "account", "login", "password", "reset", "security", "update", "billing", "session", "urgent"}
BRAND_NAMES = {"facebook", "instagram", "microsoft", "google", "linkedin", "twitter", "amazon"}

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
    try:
        if file_path.endswith(".txt"):
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()
        elif file_path.endswith(".docx"):
            doc = docx.Document(file_path)
            return " ".join(p.text for p in doc.paragraphs)
        else:
            print("[⚠️] Unsupported file type. Use .txt or .docx.")
            return ""
    except Exception as e:
        print(f"[ERROR] Could not read file: {e}")
        return ""

def score_keywords(text, min_length=2):
    text = text.lower()
    words = re.findall(r'\b[a-z][a-z0-9]{%d,}\b' % min_length, text)
    cleaned_words = [
        STEMMER.stem(word) for word in words
        if word not in STOPWORDS and word not in BRAND_NAMES and not word.isdigit()
    ]
    freq = Counter(cleaned_words)
    heap = [(-count, word) for word, count in freq.items()]
    heapq.heapify(heap)
    return heap

def keyword_explorer(source, prefix=None):
    content = ""
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
    count = 0
    seen_words = set()

    while scored_keywords and count < 1000:
        freq_val, word = heapq.heappop(scored_keywords)
        if word not in seen_words:
            trie.insert(word)
            top_keywords.append((word, -freq_val))
            seen_words.add(word)
            count += 1

    if prefix:
        print(f"\n🔍 Filtering keywords with prefix: '{prefix}'\n")
        matched = trie.starts_with(prefix)
        for i, word in enumerate(matched, 1):
            print(f"{i:03}. {word}")
    else:
        print(f"\n🔑 Top {len(top_keywords)} Keywords:\n")
        for i, (kw, freq) in enumerate(top_keywords, 1):
            marker = "⚠️" if kw in PHISHING_TERMS else ""
            print(f"{i:03}. {kw:<20} | Freq: {freq} {marker}")

    flagged = [kw for kw, _ in top_keywords if kw in PHISHING_TERMS]
    if flagged:
        print(f"\n🛑 Phishing Indicators Found: {', '.join(flagged)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="⚙️ Advanced Keyword Extractor with Trie + Heap + Filters")
    parser.add_argument("source", help="URL or path to .txt/.docx file")
    parser.add_argument("--prefix", help="Prefix to filter keywords", default=None)
    args = parser.parse_args()

    keyword_explorer(args.source, args.prefix)
