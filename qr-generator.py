import qrcode
from qrcode.console_scripts import main as qrcode_terminal_main
import os

def generate_qr_terminal(data):
    qr = qrcode.QRCode(border=1)
    qr.add_data(data)
    qr.make(fit=True)

    print("\n[+] Generated QR Code:\n")
    qr.print_ascii(invert=True)

    save = input("\nDo you want to save this QR as an image file? (y/n): ").strip().lower()
    if save == 'y':
        filename = input("Enter filename (e.g. myqr.png): ").strip() or "qr_code.png"
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(filename)
        print(f"[+] QR saved as {filename}")

def get_input_data():
    choice = input("Enter input type - (1) Text/URL or (2) From file: ").strip()

    if choice == '1':
        return input("Enter the text or URL to encode: ").strip()
    elif choice == '2':
        filepath = input("Enter the path to the text file: ").strip()
        if not os.path.exists(filepath):
            print("[!] File not found.")
            return None
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read().strip()
    else:
        print("[!] Invalid choice.")
        return None

def main():
    print("== Terminal QR Code Generator ==")
    data = get_input_data()
    if data:
        generate_qr_terminal(data)

if __name__ == "__main__":
    main()
