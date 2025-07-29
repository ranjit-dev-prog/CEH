import argparse
import qrcode
from urllib.parse import urlparse

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ["http", "https"] and parsed.netloc
    except:
        return False

def generate_qr(url, save_as=None):
    qr = qrcode.QRCode(border=1)
    qr.add_data(url)
    qr.make(fit=True)

    print("\n[+] Generated QR Code for:", url)
    qr.print_ascii(invert=True)

    if save_as:
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(save_as)
        print(f"[+] QR Code saved as: {save_as}")

def main():
    parser = argparse.ArgumentParser(description="QR Code Generator (URL only)")
    parser.add_argument("url", help="URL to encode in the QR code (must start with http/https)")
    parser.add_argument("--save", metavar="FILENAME", help="Optional: save QR as image (e.g., qr.png)")
    
    args = parser.parse_args()

    if not is_valid_url(args.url):
        print("[!] Invalid URL. Must start with http:// or https://")
        return

    generate_qr(args.url, args.save)

if __name__ == "__main__":
    main()
