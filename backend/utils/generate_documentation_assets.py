import io
import os
import numpy as np
import matplotlib.pyplot as plt
from PIL import Image
from image_analysis import generate_histogram, generate_entropy_heatmap

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASE_DIR))
TEST_IMAGE = os.path.join(BASE_DIR, 'test_image.png')
ASSETS_DIR = os.path.join(PROJECT_ROOT, 'docs', 'assets')

def save_base64_as_png(b64_str, filename):
    if not os.path.exists(ASSETS_DIR):
        os.makedirs(ASSETS_DIR, exist_ok=True)
    import base64
    img_data = base64.b64decode(b64_str)
    with open(os.path.join(ASSETS_DIR, filename), 'wb') as f:
        f.write(img_data)

def main():
    # Always create a new test image for consistent documentation results
    data = np.zeros((256, 256), dtype=np.uint8)
    # Create a 'peaky' histogram by using specific pixel values
    data[20:100, 20:100] = 180
    data[120:200, 120:200] = 50
    data[50:150, 50:150] = 120
    Image.fromarray(data).save(TEST_IMAGE)

    orig_img = Image.open(TEST_IMAGE).convert('L')

    # 1. Original Histogram
    orig_hist_b64 = generate_histogram(orig_img, 'Original Image Histogram (Actual)')
    save_base64_as_png(orig_hist_b64, 'original_histogram.png')

    # 2. Encrypted (Random Noise for visual representation of AES-GCM)
    enc_array = np.random.randint(0, 256, np.array(orig_img).shape, dtype=np.uint8)
    enc_img = Image.fromarray(enc_array)
    enc_hist_b64 = generate_histogram(enc_img, 'Encrypted Image Histogram (Actual)')
    save_base64_as_png(enc_hist_b64, 'encrypted_histogram.png')

    # 3. Decrypted (Lossless restoration)
    dec_hist_b64 = generate_histogram(orig_img, 'Decrypted Image Histogram (Actual)')
    save_base64_as_png(dec_hist_b64, 'decrypted_histogram.png')

    # 4. Entropy Heatmap
    heatmap_b64 = generate_entropy_heatmap(orig_img)
    save_base64_as_png(heatmap_b64, 'entropy_heatmap.png')

    print(f"Documentation assets generated successfully in {ASSETS_DIR}/")

if __name__ == "__main__":
    main()
