import time
import itertools
import sys
import random

# ---------- User Inputs ----------
email = input("Enter your email: ").strip()
username = input("Enter your username: ").strip()
phone = input("Enter your phone number: ").strip()

targets = {k: v for k, v in {"email": email, "username": username, "phone": phone}.items() if v}

# ---------- Sites List (100 popular) ----------
sites = [
    "twitter.com", "facebook.com", "instagram.com", "linkedin.com", "reddit.com",
    "github.com", "stackoverflow.com", "medium.com", "quora.com", "tumblr.com",
    "telegram.org", "discord.com", "slack.com", "skype.com", "twitch.tv",
    "spotify.com", "snapchat.com", "pinterest.com", "tiktok.com", "flickr.com",
    "dribbble.com", "behance.net", "producthunt.com", "vimeo.com", "soundcloud.com",
    "meetup.com", "digg.com", "flipboard.com", "deviantart.com", "ok.ru",
    "badoo.com", "weheartit.com", "9gag.com", "slideshare.net", "newgrounds.com",
    "gaiaonline.com", "last.fm", "stumbleupon.com", "livejournal.com", "myspace.com",
    "meetme.com", "myheritage.com", "soundclick.com", "letterboxd.com", "untappd.com",
    "wordpress.com", "blogger.com", "yelp.com", "airbnb.com", "amazon.com",
    "ebay.com", "aliexpress.com", "flipkart.com", "etsy.com", "shopify.com",
    "netflix.com", "hulu.com", "disneyplus.com", "primevideo.com", "hotstar.com",
    "imdb.com", "rottentomatoes.com", "goodreads.com", "coursera.org", "udemy.com",
    "edx.org", "khanacademy.org", "udacity.com", "pluralsight.com", "skillshare.com",
    "zoom.us", "teams.microsoft.com", "slido.com", "clubhouse.com", "periscope.tv",
    "wechat.com", "line.me", "kakao.com", "viber.com", "whatsapp.com",
    "openai.com", "huggingface.co", "kaggle.com", "gitlab.com", "bitbucket.org",
    "archive.org", "waybackmachine.org", "duckduckgo.com", "yahoo.com", "bing.com",
    "google.com", "icloud.com", "protonmail.com", "zoho.com", "mail.com"
]

# ---------- Loader ----------
def loader_running(duration=5):
    spinner = itertools.cycle(['|', '/', '-', '\\'])
    end_time = time.time() + duration
    while time.time() < end_time:
        sys.stdout.write(next(spinner))
        sys.stdout.flush()
        time.sleep(0.1)
        sys.stdout.write('\b')

# ---------- Fake Scan ----------
print("\n[INFO] Starting OSINT credential scan...\n")
alerts = []

for site in sites:
    print(f"[INFO] Scanning {site} ... ", end="")
    loader_running(0.5)  # show loader for half second
    
    # Fake detection: 20% chance of "found"
    if random.random() < 0.2:
        key, value = random.choice(list(targets.items()))
        msg = f"[ALERT] {key} '{value}' found on {site}"
        print("FOUND!")
        print("   " + msg)
        alerts.append(msg)
    else:
        print("SAFE")

# ---------- Final Message ----------
if not alerts:
    print("\n✅ Your credentials are safe! No matches found.")
else:
    print(f"\n⚠️ Scan complete. {len(alerts)} potential exposures detected.")
