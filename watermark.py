import cv2
import numpy as np
from rembg import remove
import os

def add_watermark(image_path, text="AD", output_path=None):
    if not os.path.isfile(image_path):
        print(f"Error: File not found: {image_path}")
        return

    image = cv2.imread(image_path)
    h, w = image.shape[:2]

    cv2.putText(image, text, (w - 100, h - 20), cv2.FONT_HERSHEY_SIMPLEX,
                2, (0, 0, 255), 5, cv2.LINE_AA)

    if not output_path:
        output_path = os.path.splitext(image_path)[0] + "_watermarked.jpg"

    cv2.imwrite(output_path, image)
    print(f"Watermarked image saved as: {output_path}")

def remove_watermark(image_path, output_path=None):
    if not os.path.isfile(image_path):
        print(f"Error: File not found: {image_path}")
        return

    image = cv2.imread(image_path)
    hsv = cv2.cvtColor(image, cv2.COLOR_BGR2HSV)

    # Detect red watermark
    lower_red1 = np.array([0, 100, 100])
    upper_red1 = np.array([10, 255, 255])
    mask1 = cv2.inRange(hsv, lower_red1, upper_red1)

    lower_red2 = np.array([160, 100, 100])
    upper_red2 = np.array([180, 255, 255])
    mask2 = cv2.inRange(hsv, lower_red2, upper_red2)

    mask = cv2.bitwise_or(mask1, mask2)
    result = cv2.inpaint(image, mask, inpaintRadius=3, flags=cv2.INPAINT_TELEA)

    if not output_path:
        output_path = os.path.splitext(image_path)[0] + "_no_watermark.jpg"

    cv2.imwrite(output_path, result)
    print(f"Watermark removed image saved as: {output_path}")

def remove_background(image_path, output_path=None, new_bg_color=(255, 255, 255)):
    if not os.path.isfile(image_path):
        print(f"Error: File not found: {image_path}")
        return

    input_image = cv2.imread(image_path)

    # Remove background using rembg
    result = remove(input_image)

    # Convert to BGR for OpenCV
    result_bgr = cv2.cvtColor(result, cv2.COLOR_RGBA2BGR)

    # Replace transparent areas with chosen background color
    alpha_channel = result[:, :, 3] / 255.0
    for c in range(3):
        result_bgr[:, :, c] = (result_bgr[:, :, c] * alpha_channel +
                               new_bg_color[c] * (1 - alpha_channel))

    if not output_path:
        output_path = os.path.splitext(image_path)[0] + "_bg_removed.jpg"

    cv2.imwrite(output_path, result_bgr)
    print(f"Background removed / replaced image saved as: {output_path}")

def main():
    print("=== Watermark & Background Tool (Advanced) ===")
    image_path = input("Enter full image path (include filename and extension): ").strip()
    image_path = image_path.replace("\\", "/")

    if not os.path.isfile(image_path):
        print("Error: File does not exist.")
        return

    print("Options:\n1. Add Watermark\n2. Remove Watermark\n3. Remove / Change Background Color")
    choice = input("Enter your choice (1, 2, or 3): ").strip()

    if choice == "1":
        text = input("Enter watermark text (default 'AD'): ").strip()
        if not text:
            text = "AD"
        add_watermark(image_path, text)
    elif choice == "2":
        remove_watermark(image_path)
    elif choice == "3":
        print("Enter new background color (B G R) each 0-255, separated by space:")
        color_input = input("Example: 255 255 255 for white: ").strip().split()
        if len(color_input) != 3:
            color = [255, 255, 255]
        else:
            color = [int(c) for c in color_input]
        remove_background(image_path, new_bg_color=color)
    else:
        print("Invalid choice!")

if __name__ == "__main__":
    main()
