from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def encrypt_aes_key(aes_key: bytes, public_key_path: str) -> bytes:
    """
    Encrypt AES key using recipient's RSA public key (OAEP).
    """
    with open(public_key_path, "rb") as f:
        public_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(aes_key)


def decrypt_aes_key(encrypted_key: bytes, private_key_path: str) -> bytes:
    """
    Decrypt AES key using recipient's RSA private key (OAEP).
    """
    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_key)
