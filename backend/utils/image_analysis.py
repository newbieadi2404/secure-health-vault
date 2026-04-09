import io
import base64
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
from PIL import Image
import seaborn as sns

matplotlib.use('Agg')  # Set non-interactive backend for thread safety on macOS


def calculate_npcr(img1, img2):
    """Number of Pixels Change Rate"""
    img1 = np.array(img1)
    img2 = np.array(img2)
    if img1.shape != img2.shape:
        # Resize img2 to match img1 if needed
        from PIL import Image
        img2 = np.array(
            Image.fromarray(img2).resize((img1.shape[1], img1.shape[0]))
        )

    diff = img1 != img2
    return (np.sum(diff) / img1.size) * 100


def calculate_uaci(img1, img2):
    """Unified Average Changing Intensity"""
    img1 = np.array(img1).astype(np.float64)
    img2 = np.array(img2).astype(np.float64)
    if img1.shape != img2.shape:
        from PIL import Image
        img2 = np.array(
            Image.fromarray(img2.astype(np.uint8)).resize(
                (img1.shape[1], img1.shape[0])
            )
        ).astype(np.float64)

    diff = np.abs(img1 - img2)
    return (np.sum(diff) / (255 * img1.size)) * 100


def calculate_correlation(img):
    """Calculate adjacent pixel correlation (horizontal)"""
    img_array = np.array(img).astype(np.float64)
    if len(img_array.shape) == 3:
        # Convert to grayscale for correlation
        img_array = np.mean(img_array, axis=2)

    x = img_array[:, :-1].flatten()
    y = img_array[:, 1:].flatten()

    if len(x) < 2:
        return 0
    return np.corrcoef(x, y)[0, 1]


def calculate_entropy(img):
    """Calculate Shannon Entropy"""
    img_array = np.array(img).flatten()
    counts = np.bincount(img_array, minlength=256)
    probs = counts / len(img_array)
    probs = probs[probs > 0]
    return -np.sum(probs * np.log2(probs))


def calculate_psnr(original, encrypted):
    """Peak Signal-to-Noise Ratio"""
    mse = np.mean((np.array(original) - np.array(encrypted)) ** 2)
    if mse == 0:
        return 100
    max_pixel = 255.0
    return 20 * np.log10(max_pixel / np.sqrt(mse))


def generate_histogram(img, title):
    """Generate histogram plot as base64 string"""
    plt.figure(figsize=(6, 4))
    img_array = np.array(img).flatten()
    plt.hist(img_array, bins=256, color='blue', alpha=0.7)
    plt.title(title)
    plt.xlabel('Pixel Value')
    plt.ylabel('Frequency')

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    plt.close()
    return base64.b64encode(buf.getvalue()).decode('utf-8')


def generate_correlation_plot(img, title):
    """Generate correlation plot of adjacent pixels (horizontal)"""
    img_array = np.array(img).astype(np.float64)
    if len(img_array.shape) == 3:
        img_array = np.mean(img_array, axis=2)

    x = img_array[:, :-1].flatten()
    y = img_array[:, 1:].flatten()

    # Sample if too large
    if len(x) > 5000:
        indices = np.random.choice(len(x), 5000, replace=False)
        x = x[indices]
        y = y[indices]

    plt.figure(figsize=(6, 5))
    plt.scatter(x, y, s=1, alpha=0.5, color='blue')
    plt.title(title)
    plt.xlabel('Pixel value (x, y)')
    plt.ylabel('Pixel value (x+1, y)')
    plt.xlim(0, 255)
    plt.ylim(0, 255)
    plt.grid(True, linestyle='--', alpha=0.3)

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    plt.close()
    return base64.b64encode(buf.getvalue()).decode('utf-8')


def generate_entropy_heatmap(img):
    """Generate local entropy heatmap"""
    from skimage.filters.rank import entropy as local_entropy
    from skimage.morphology import disk
    from skimage.color import rgb2gray

    img_array = np.array(img)
    if len(img_array.shape) == 3:
        img_array = rgb2gray(img_array)

    # local_entropy expects uint8
    if img_array.max() <= 1.0:
        img_uint8 = (img_array * 255).astype(np.uint8)
    else:
        img_uint8 = img_array.astype(np.uint8)

    entr_img = local_entropy(img_uint8, disk(5))

    plt.figure(figsize=(6, 4))
    sns.heatmap(entr_img, cmap='viridis')
    plt.title('Local Entropy Heatmap')
    plt.axis('off')

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    plt.close()
    return base64.b64encode(buf.getvalue()).decode('utf-8')


def apply_salt_and_pepper(img, amount=0.01):
    """Apply salt and pepper noise for attack analysis"""
    img_array = np.array(img).copy()

    # Salt
    num_salt = np.ceil(amount * img_array.size * 0.5)
    coords = [
        np.random.randint(0, i - 1, int(num_salt)) for i in img_array.shape
    ]
    img_array[tuple(coords)] = 255

    # Pepper
    num_pepper = np.ceil(amount * img_array.size * 0.5)
    coords = [
        np.random.randint(0, i - 1, int(num_pepper)) for i in img_array.shape
    ]
    img_array[tuple(coords)] = 0

    return Image.fromarray(img_array)


def apply_bit_flipping(img, bit_pos=0):
    """Simulate bit flipping attack"""
    img_array = np.array(img).copy()
    # Flip the specified bit for 1% of pixels
    mask = 1 << bit_pos
    num_pixels = int(0.01 * img_array.size)
    indices = [
        np.random.randint(0, i - 1, num_pixels) for i in img_array.shape
    ]
    img_array[tuple(indices)] ^= mask
    return Image.fromarray(img_array)


def apply_compression(img, quality=50):
    """Simulate data compression attack"""
    buf = io.BytesIO()
    img.save(buf, format='JPEG', quality=quality)
    buf.seek(0)
    return Image.open(buf)

