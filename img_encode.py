from PIL import Image
import os
import sys

# Encode a message into an image
def encode_image(image_path, message):
    img = Image.open(image_path)
    encoded = img.copy()
    width, height = img.size
    message += "~~~"  # delimiter
    binary_msg = ''.join([format(ord(i), "08b") for i in message])
    msg_len = len(binary_msg)
    idx = 0

    for y in range(height):
        for x in range(width):
            pixel = list(img.getpixel((x, y)))
            for n in range(3):
                if idx < msg_len:
                    pixel[n] = pixel[n] & ~1 | int(binary_msg[idx])
                    idx += 1
            encoded.putpixel((x, y), tuple(pixel))
            if idx >= msg_len:
                # Auto output path
                base, ext = os.path.splitext(image_path)
                output_path = f"{base}_encoded{ext}"
                encoded.save(output_path)
                print(f"[+] Message encoded successfully into {output_path}")
                return
    print("[!] Message too long for this image.")

# Decode a message from an image
def decode_image(image_path):
    img = Image.open(image_path)
    binary_msg = ""
    max_bits = img.width * img.height * 3
    bits_read = 0

    for y in range(img.height):
        for x in range(img.width):
            pixel = list(img.getpixel((x, y)))
            for n in range(3):
                binary_msg += str(pixel[n] & 1)
                bits_read += 1

                if len(binary_msg) >= 8:
                    all_bytes = [binary_msg[i:i+8] for i in range(0, len(binary_msg), 8)]
                    message = ""
                    for byte in all_bytes:
                        char = chr(int(byte, 2))
                        message += char
                        if message[-3:] == "~~~":
                            print("[+] Hidden message:", message[:-3])
                            return
                if bits_read >= max_bits:
                    break

    print("[!] No hidden message found in this image.")

# Menu
def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <image_path>")
        return

    image_path = sys.argv[1].strip().strip('"')

    if not os.path.isfile(image_path):
        print("[!] File does not exist.")
        return

    print("=== Steganography Tool ===")
    print("\nChoose an option:")
    print("1. Encode a message")
    print("2. Decode a message")
    choice = input("Enter 1 or 2: ")

    if choice == "1":
        message = input("Enter the message to hide: ")
        encode_image(image_path, message)
    elif choice == "2":
        decode_image(image_path)
    else:
        print("[!] Invalid choice")

if __name__ == "__main__":
    main()
