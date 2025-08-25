import cv2
import numpy as np
import os
from rembg import remove


def add_watermark(image_path, text=None, watermark_path=None, output_path=None,
                  position="bottom-right", scale=0.2, opacity=0.5,
                  text_color=(128, 128, 128)):
    """
    Add a text or image watermark with adjustable opacity, scaling, and color.

    :param image_path: Path to input image
    :param text: Text to use as watermark (if no watermark_path)
    :param watermark_path: Path to watermark image (optional)
    :param output_path: Path to save result (optional)
    :param position: Watermark position (top-left, top-right, bottom-left, bottom-right, center)
    :param scale: Scaling factor (for image watermark)
    :param opacity: Transparency (0=transparent, 1=solid)
    :param text_color: Color for text watermark in BGR format (default gray)
    """
    if not os.path.isfile(image_path):
        print(f"❌ File not found: {image_path}")
        return

    image = cv2.imread(image_path)
    h_img, w_img = image.shape[:2]

    # === IMAGE WATERMARK ===
    if watermark_path and os.path.isfile(watermark_path):
        watermark = cv2.imread(watermark_path, cv2.IMREAD_UNCHANGED)

        # Resize watermark
        w_scale = int(w_img * scale)
        h_scale = int(watermark.shape[0] * (w_scale / watermark.shape[1]))
        watermark = cv2.resize(watermark, (w_scale, h_scale), interpolation=cv2.INTER_AREA)

        # Handle transparency
        if watermark.shape[2] == 4:
            wm_b, wm_g, wm_r, wm_a = cv2.split(watermark)
            mask = wm_a / 255.0
        else:
            wm_b, wm_g, wm_r = cv2.split(watermark)
            mask = np.ones(wm_b.shape, dtype=float)

        watermark_rgb = cv2.merge((wm_b, wm_g, wm_r))
        mask *= opacity

        # Position watermark
        x, y = get_position(position, w_img, h_img, w_scale, h_scale)

        roi = image[y:y + h_scale, x:x + w_scale]
        for c in range(3):
            roi[:, :, c] = (roi[:, :, c] * (1 - mask) +
                            watermark_rgb[:, :, c] * mask).astype(np.uint8)

        image[y:y + h_scale, x:x + w_scale] = roi

    # === TEXT WATERMARK ===
    elif text:
        font_scale = w_img / 1000
        thickness = max(1, int(w_img / 500))
        text_size, _ = cv2.getTextSize(text, cv2.FONT_HERSHEY_SIMPLEX, font_scale, thickness)
        tw, th = text_size

        x, y = get_position(position, w_img, h_img, tw, th, text=True)

        overlay = image.copy()
        cv2.putText(overlay, text, (x, y), cv2.FONT_HERSHEY_SIMPLEX,
                    font_scale, text_color, thickness, cv2.LINE_AA)

        # Blend with opacity
        image = cv2.addWeighted(overlay, opacity, image, 1 - opacity, 0)

    else:
        print("❌ No watermark (text or image) provided.")
        return

    if not output_path:
        output_path = os.path.splitext(image_path)[0] + "_watermarked.jpg"

    cv2.imwrite(output_path, image)
    print(f"✅ Watermarked image saved as: {output_path}")


def get_position(position, w_img, h_img, w, h, text=False):
    """Helper: calculate position for watermark or text."""
    if position == "bottom-right":
        return w_img - w - 10, h_img - (10 if text else h) - 10
    elif position == "bottom-left":
        return 10, h_img - (10 if text else h) - 10
    elif position == "top-left":
        return 10, (h if text else 10) + 10
    elif position == "top-right":
        return w_img - w - 10, (h if text else 10) + 10
    elif position == "center":
        return (w_img - w) // 2, (h_img + (h if text else h)) // 2
    else:
        return 10, h_img - 10


def get_position(position, w_img, h_img, w, h, text=False):
    """Helper: calculate position for watermark or text."""
    if position == "bottom-right":
        return w_img - w - 10, h_img - (10 if text else h) - 10
    elif position == "bottom-left":
        return 10, h_img - (10 if text else h) - 10
    elif position == "top-left":
        return 10, (h if text else 10) + 10
    elif position == "top-right":
        return w_img - w - 10, (h if text else 10) + 10
    elif position == "center":
        return (w_img - w) // 2, (h_img + (h if text else h)) // 2
    else:
        return 10, h_img - 10


def remove_watermark(image_path, output_path=None):
    """
    Remove red-colored watermarks using inpainting.
    """
    if not os.path.isfile(image_path):
        print(f"❌ File not found: {image_path}")
        return

    image = cv2.imread(image_path)
    hsv = cv2.cvtColor(image, cv2.COLOR_BGR2HSV)

    # Red color ranges
    mask1 = cv2.inRange(hsv, np.array([0, 100, 100]), np.array([10, 255, 255]))
    mask2 = cv2.inRange(hsv, np.array([160, 100, 100]), np.array([180, 255, 255]))
    mask = cv2.bitwise_or(mask1, mask2)

    result = cv2.inpaint(image, mask, inpaintRadius=3, flags=cv2.INPAINT_TELEA)

    if not output_path:
        output_path = os.path.splitext(image_path)[0] + "_no_watermark.jpg"

    cv2.imwrite(output_path, result)
    print(f"✅ Watermark removed image saved as: {output_path}")


def remove_background(image_path, output_path=None, new_bg_color=(255, 255, 255)):
    """
    Remove background using rembg and replace with solid color.
    """
    if not os.path.isfile(image_path):
        print(f"❌ File not found: {image_path}")
        return

    with open(image_path, "rb") as f:
        input_image = f.read()

    result = remove(input_image)  # returns RGBA
    result = cv2.imdecode(np.frombuffer(result, np.uint8), cv2.IMREAD_UNCHANGED)

    # Separate alpha channel
    alpha = result[:, :, 3] / 255.0
    result_bgr = result[:, :, :3].copy()

    for c in range(3):
        result_bgr[:, :, c] = (result_bgr[:, :, c] * alpha +
                               new_bg_color[c] * (1 - alpha))

    if not output_path:
        output_path = os.path.splitext(image_path)[0] + "_bg_changed.jpg"

    cv2.imwrite(output_path, result_bgr)
    print(f"✅ Background processed image saved as: {output_path}")


def main():
    print("\n=== Watermark & Background Tool ===")
    image_path = input("Enter full image path (with extension): ").strip().replace("\\", "/")

    if not os.path.isfile(image_path):
        print("❌ Error: File does not exist.")
        return

    print("\nOptions:")
    print("1. Add Watermark")
    print("2. Remove Watermark")
    print("3. Remove / Change Background Color")

    choice = input("Enter your choice (1, 2, or 3): ").strip()

    if choice == "1":
        use_image = input("Do you want to use an image watermark? (y/n): ").strip().lower()
        if use_image == "y":
            wm_path = input("Enter watermark image path: ").strip()
            add_watermark(image_path, watermark_path=wm_path, opacity=0.5, scale=0.2)
        else:
            text = input("Enter watermark text (default 'AD'): ").strip() or "AD"
            add_watermark(image_path, text=text, opacity=0.5)

    elif choice == "2":
        remove_watermark(image_path)

    elif choice == "3":
        print("Enter new background color (B G R), e.g. '255 255 255' for white:")
        try:
            color = list(map(int, input(">> ").strip().split()))
            if len(color) != 3:
                raise ValueError
        except ValueError:
            color = [255, 255, 255]
            print("⚠️ Invalid input, defaulting to white background.")

        remove_background(image_path, new_bg_color=tuple(color))

    else:
        print("❌ Invalid choice!")


if __name__ == "__main__":
    main()
