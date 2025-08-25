import time
import itertools
import sys
import hashlib

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
    "google.com", "icloud.com", "protonmail.com", "zoho.com", "mail.com",
    
    # Additional 100+ sites
    # Social Media & Messaging
    "signal.org", "threads.net", "truthsocial.com", "gab.com", "parler.com",
    "mastodon.social", "diasporafoundation.org", "ello.co", "vk.com", "xing.com",
    "nextdoor.com", "care2.com", "couchsurfing.com", "ravelry.com", "mixi.jp",
    "plurk.com", "renren.com", "douban.com", "weibo.com", "qq.com",
    "zalo.me", "kik.com", "wickr.com", "threema.ch", "wire.com",
    
    # Video & Streaming
    "dailymotion.com", "vimeo.com", "rumble.com", "odysee.com", "peertube.tv",
    "caffeine.tv", "bigo.tv", "younow.com", "streamyard.com", "restream.io",
    "vlive.tv", "afreecatv.com", "niconico.jp", "bilibili.tv", "twitch.tv",
    
    # Audio & Music
    "apple.com/music", "pandora.com", "iheart.com", "deezer.com", "tidal.com",
    "bandcamp.com", "mixcloud.com", "audiomack.com", "reverbnation.com", "anchor.fm",
    "spreaker.com", "libsyn.com", "podbean.com", "castbox.fm", "stitcher.com",
    
    # Gaming
    "steampowered.com", "epicgames.com", "origin.com", "gog.com", "ubisoft.com",
    "roblox.com", "minecraft.net", "nexusmods.com", "moddb.com", "indiedb.com",
    "gamejolt.com", "itch.io", "kongregate.com", "armorgames.com", "miniclip.com",
    
    # Creative & Design
    "artstation.com", "deviantart.com", "500px.com", "vsco.co", "canva.com",
    "figma.com", "adobe.com", "notion.so", "miro.com", "trello.com",
    "asana.com", "basecamp.com", "clickup.com", "airtable.com", "notion.so",
    
    # E-commerce & Shopping
    "walmart.com", "target.com", "bestbuy.com", "newegg.com", "wayfair.com",
    "overstock.com", "zappos.com", "asos.com", "zalando.com", "poshmark.com",
    "depop.com", "mercari.com", "offerup.com", "letgo.com", "craigslist.org",
    
    # News & Content
    "substack.com", "ghost.org", "medium.com", "dev.to", "hashnode.com",
    "news.ycombinator.com", "alltop.com", "feedly.com", "inoreader.com", "flipboard.com",
    
    # Education & Learning
    "brilliant.org", "masterclass.com", "codecademy.com", "freecodecamp.org", "w3schools.com",
    "sololearn.com", "datacamp.com", "dataquest.io", "treehouse.com", "lynda.com",
    
    # Productivity & Tools
    "dropbox.com", "box.com", "pcloud.com", "mega.nz", "mediafire.com",
    "wetransfer.com", "sendspace.com", "grammarly.com", "hemingwayapp.com", "notion.so",
    
    # Dating
    "tinder.com", "bumble.com", "hinge.co", "okcupid.com", "match.com",
    "zoosk.com", "grindr.com", "scruff.com", "her.com", "feeld.co",
    
    # Food & Delivery
    "doordash.com", "ubereats.com", "grubhub.com", "postmates.com", "deliveroo.com",
    "justeat.co.uk", "swiggy.com", "zomato.com", "opentable.com", "resy.com",
    
    # Travel
    "booking.com", "expedia.com", "kayak.com", "skyscanner.net", "tripadvisor.com",
    "bookingbuddy.com", "hotels.com", "orbitz.com", "travelocity.com", "agoda.com",
    
    # Health & Fitness
    "myfitnesspal.com", "strava.com", "fitbit.com", "runkeeper.com", "endomondo.com",
    "mapmyrun.com", "headspace.com", "calm.com", "noom.com", "peloton.com",
    
    # Finance
    "paypal.com", "venmo.com", "cash.app", "zellepay.com", "revolut.com",
    "transferwise.com", "robinhood.com", "coinbase.com", "binance.com", "kraken.com",
    
    # Cloud & Storage
    "google.com/drive", "icloud.com", "onedrive.live.com", "mega.nz", "pcloud.com",
    "dropbox.com", "box.com", "sync.com", "tresorit.com", "spideroak.com"
]
# ---------- Loader ----------
def loader_running(duration=0.3):
    spinner = itertools.cycle(['|', '/', '-', '\\'])
    end_time = time.time() + duration
    while time.time() < end_time:
        sys.stdout.write(next(spinner))
        sys.stdout.flush()
        time.sleep(0.1)
        sys.stdout.write('\b')

# ---------- Deterministic Fake Scan ----------
def credential_found(site, target):
    """Hash site+target -> decide deterministically if 'found'"""
    h = hashlib.sha256((site + target).encode()).hexdigest()
    return int(h, 16) % 7 == 0   # ~1 in 7 chance

print("\n[INFO] Starting OSINT credential scan...\n")
alerts = []

for site in sites:
    print(f"[INFO] Scanning {site} ... ", end="")
    loader_running(0.3)  # short loader
    
    found = False
    for key, value in targets.items():
        if credential_found(site, value):
            msg = f"[ALERT] {key} '{value}' found on {site}"
            print("FOUND!")
            print("   " + msg)
            alerts.append(msg)
            found = True
            break
    
    if not found:
        print("SAFE")

# ---------- Final Message ----------
if not alerts:
    print("\n✅ Your credentials are safe! No matches found.")
else:
    print(f"\n⚠️ Scan complete. {len(alerts)} potential exposures detected.")
