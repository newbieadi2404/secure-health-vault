from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

AES_KEY_SIZE = 32  # 256-bit
NONCE_SIZE = 12    # Recommended for GCM


def generate_aes_key():
    return get_random_bytes(AES_KEY_SIZE)


def encrypt_gcm(plaintext: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(NONCE_SIZE))
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, cipher.nonce, tag


def decrypt_gcm(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
