import argparse
import os
import qrcode

def generate_qr_terminal(data, save_as=None):
    qr = qrcode.QRCode(border=1)
    qr.add_data(data)
    qr.make(fit=True)

    print("\n[+] Generated QR Code:\n")
    qr.print_ascii(invert=True)

    if save_as:
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(save_as)
        print(f"[+] QR saved as {save_as}")

def main():
    parser = argparse.ArgumentParser(description="Terminal QR Code Generator")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--text", help="Text or URL to encode in the QR code")
    group.add_argument("--file", help="Path to a file containing the data to encode")
    parser.add_argument("--save", metavar="FILENAME", help="Save QR as an image (e.g. qr.png)")

    args = parser.parse_args()

    if args.text:
        data = args.text
    elif args.file:
        if not os.path.exists(args.file):
            print("[!] File not found.")
            return
        with open(args.file, 'r', encoding='utf-8') as f:
            data = f.read().strip()
    else:
        print("[!] No input provided.")
        return

    generate_qr_terminal(data, args.save)

if __name__ == "__main__":
    main()
