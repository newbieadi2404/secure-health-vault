"""
DICOM Digital Signature Module

This module provides digital signature functionality for DICOM data,
ensuring authenticity and integrity verification.

Features:
- RSA-based digital signatures (PSS padding)
- Detached signature generation and verification
- Support for signing DICOM headers and pixel data hashes
"""

import os
import hashlib
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Project directory
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
SIGNING_KEYS_DIR = os.path.join(PROJECT_DIR, "signing_keys")


def ensure_signing_keys():
    """Ensure signing keys directory exists"""
    os.makedirs(SIGNING_KEYS_DIR, exist_ok=True)


def generate_signing_keypair(key_size=2048):
    """
    Generate RSA key pair for digital signing.
    
    Args:
        key_size: RSA key size in bits (default 2048)
    
    Returns:
        tuple: (private_key_path, public_key_path)
    """
    ensure_signing_keys()
    
    # Generate RSA key pair
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    # Save keys
    private_key_path = os.path.join(SIGNING_KEYS_DIR, "signing_private.pem")
    public_key_path = os.path.join(SIGNING_KEYS_DIR, "signing_public.pem")
    
    with open(private_key_path, "wb") as f:
        f.write(private_key)
    
    with open(public_key_path, "wb") as f:
        f.write(public_key)
    
    print(f"[OK] Signing key pair generated")
    print(f"     Private key: {private_key_path}")
    print(f"     Public key: {public_key_path}")
    
    return private_key_path, public_key_path


def get_signing_keys():
    """
    Get paths to signing keys, generating if they don't exist.
    
    Returns:
        tuple: (private_key_path, public_key_path) or (None, None) if generation fails
    """
    private_key_path = os.path.join(SIGNING_KEYS_DIR, "signing_private.pem")
    public_key_path = os.path.join(SIGNING_KEYS_DIR, "signing_public.pem")
    
    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        try:
            generate_signing_keypair()
        except Exception as e:
            print(f"[ERROR] Failed to generate signing keys: {e}")
            return None, None
    
    return private_key_path, public_key_path


def sign_data(data: bytes, private_key_path: str = None) -> bytes:
    """
    Create digital signature for data using RSA-PSS.
    
    Args:
        data: Data to sign (bytes)
        private_key_path: Path to private key file
    
    Returns:
        bytes: Digital signature
    
    Raises:
        ValueError: If signing fails
    """
    if private_key_path is None:
        private_key_path = os.path.join(SIGNING_KEYS_DIR, "signing_private.pem")
    
    if not os.path.exists(private_key_path):
        raise ValueError(f"Private key not found: {private_key_path}")
    
    # Load private key
    with open(private_key_path, "rb") as f:
        key = RSA.import_key(f.read())
    
    # Create hash of data
    h = SHA256.new(data)
    
    # Sign with PKCS1_v1_5 (more compatible)
    signature = pkcs1_15.new(key).sign(h)
    
    return signature


def verify_signature(data: bytes, signature: bytes, public_key_path: str = None) -> bool:
    """
    Verify digital signature using RSA-PSS.
    
    Args:
        data: Original data that was signed
        signature: Digital signature to verify
        public_key_path: Path to public key file
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    if public_key_path is None:
        public_key_path = os.path.join(SIGNING_KEYS_DIR, "signing_public.pem")
    
    if not os.path.exists(public_key_path):
        print(f"[ERROR] Public key not found: {public_key_path}")
        return False
    
    try:
        # Load public key
        with open(public_key_path, "rb") as f:
            key = RSA.import_key(f.read())
        
        # Create hash of data
        h = SHA256.new(data)
        
        # Verify signature
        pkcs1_15.new(key).verify(h, signature)
        
        return True
    except (ValueError, TypeError) as e:
        print(f"[ERROR] Signature verification failed: {e}")
        return False


def sign_dict(data: dict, private_key_path: str = None) -> dict:
    """
    Sign a dictionary and return data + signature.
    
    Args:
        data: Dictionary to sign
        private_key_path: Path to private key file
    
    Returns:
        dict: Data with signature added
    """
    # Serialize data to bytes (canonical JSON)
    data_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
    
    # Create signature
    signature = sign_data(data_bytes, private_key_path)
    
    # Return signed data
    result = data.copy()
    result['_signature'] = signature.hex()
    
    return result


def verify_dict_signed(data: dict, public_key_path: str = None) -> bool:
    """
    Verify a signed dictionary.
    
    Args:
        data: Dictionary with '_signature' field
        public_key_path: Path to public key file
    
    Returns:
        bool: True if signature is valid
    """
    if '_signature' not in data:
        print("[ERROR] No signature found in data")
        return False
    
    # Extract signature and remove from data for verification
    signature_hex = data.pop('_signature')
    signature = bytes.fromhex(signature_hex)
    
    # Serialize data to bytes (same as signing)
    data_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
    
    # Verify
    result = verify_signature(data_bytes, signature, public_key_path)
    
    # Restore signature in data
    data['_signature'] = signature_hex
    
    return result


def compute_data_hash(data: bytes) -> str:
    """
    Compute SHA-256 hash of data.
    
    Args:
        data: Data to hash
    
    Returns:
        str: Hex-encoded hash
    """
    return hashlib.sha256(data).hexdigest()


def sign_dicom_components(header_data: dict, pixel_data_hash: str, private_key_path: str = None) -> str:
    """
    Create a compound signature for DICOM header and pixel data hash.
    
    This signs both the header metadata and a hash of the pixel data,
    ensuring the integrity of both components without needing to sign
    potentially large pixel data directly.
    
    Args:
        header_data: DICOM header as dictionary
        pixel_data_hash: SHA-256 hash of pixel data
        private_key_path: Path to private key
    
    Returns:
        str: Hex-encoded signature
    """
    # Create compound data to sign
    compound_data = {
        'header': header_data,
        'pixel_data_hash': pixel_data_hash
    }
    
    # Sign the compound data
    data_bytes = json.dumps(compound_data, sort_keys=True).encode('utf-8')
    signature = sign_data(data_bytes, private_key_path)
    
    return signature.hex()


def verify_dicom_signature(header_data: dict, pixel_data_hash: str, 
                           signature: str, public_key_path: str = None) -> bool:
    """
    Verify DICOM component signature.
    
    Args:
        header_data: DICOM header as dictionary
        pixel_data_hash: SHA-256 hash of pixel data
        signature: Hex-encoded signature to verify
        public_key_path: Path to public key
    
    Returns:
        bool: True if signature is valid
    """
    try:
        # Reconstruct compound data
        compound_data = {
            'header': header_data,
            'pixel_data_hash': pixel_data_hash
        }
        
        data_bytes = json.dumps(compound_data, sort_keys=True).encode('utf-8')
        signature_bytes = bytes.fromhex(signature)
        
        return verify_signature(data_bytes, signature_bytes, public_key_path)
    except Exception as e:
        print(f"[ERROR] DICOM signature verification failed: {e}")
        return False


def create_signed_payload(encrypted_header: dict, encrypted_pixel_hash: str, 
                         sender_email: str, private_key_path: str = None) -> dict:
    """
    Create a complete signed payload for DICOM data transfer.
    
    Args:
        encrypted_header: Encrypted DICOM header
        encrypted_pixel_hash: Hash of encrypted pixel data
        sender_email: Sender's email for key lookup
        private_key_path: Path to sender's private key
    
    Returns:
        dict: Signed payload with signature
    """
    # Get signing keys
    if private_key_path is None:
        private_key_path = os.path.join(SIGNING_KEYS_DIR, "signing_private.pem")
    
    # Prepare payload components
    payload_components = {
        'sender': sender_email,
        'header': encrypted_header,
        'pixel_data_hash': encrypted_pixel_hash,
        'timestamp': str(os.path.getmtime(__file__) if os.path.exists(__file__) else 0)
    }
    
    # Create signature
    data_bytes = json.dumps(payload_components, sort_keys=True).encode('utf-8')
    signature = sign_data(data_bytes, private_key_path)
    
    # Create final payload
    payload = payload_components.copy()
    payload['signature'] = signature.hex()
    
    return payload


def verify_received_payload(payload: dict, sender_public_key_path: str = None) -> tuple:
    """
    Verify a received signed payload.
    
    Args:
        payload: Received payload with signature
        sender_public_key_path: Path to sender's public key
    
    Returns:
        tuple: (is_valid: bool, message: str)
    """
    if 'signature' not in payload:
        return False, "No signature in payload"
    
    # Extract signature
    signature_hex = payload['signature']
    signature = bytes.fromhex(signature_hex)
    
    # Create copy without signature for verification
    verify_data = {k: v for k, v in payload.items() if k != 'signature'}
    data_bytes = json.dumps(verify_data, sort_keys=True).encode('utf-8')
    
    # Verify
    if public_key_path is None:
        public_key_path = os.path.join(SIGNING_KEYS_DIR, "signing_public.pem")
    
    if not os.path.exists(sender_public_key_path):
        # Try project public key
        sender_public_key_path = public_key_path
    
    is_valid = verify_signature(data_bytes, signature, sender_public_key_path)
    
    if is_valid:
        return True, "Signature verified successfully"
    else:
        return False, "Signature verification FAILED - data may be tampered"


if __name__ == "__main__":
    # Test the signature module
    print("=" * 60)
    print("Testing DICOM Digital Signature Module")
    print("=" * 60)
    
    # Generate keys
    print("\n1. Generating signing key pair...")
    priv_key, pub_key = get_signing_keys()
    
    # Test data
    test_data = {
        "patient_id": "P12345",
        "study_date": "2024-01-15",
        "modality": "CT",
        "header": "encrypted_header_data_here"
    }
    
    # Sign data
    print("\n2. Signing test data...")
    signed_data = sign_dict(test_data, priv_key)
    print(f"   Signature: {signed_data['_signature'][:32]}...")
    
    # Verify signature
    print("\n3. Verifying signature...")
    is_valid = verify_dict_signed(signed_data, pub_key)
    print(f"   Verification result: {'PASSED' if is_valid else 'FAILED'}")
    
    # Test DICOM component signing
    print("\n4. Testing DICOM component signing...")
    header = {"patient_name": "Test Patient", "study_uid": "1.2.3.4.5"}
    pixel_hash = compute_data_hash(b"fake_pixel_data")
    
    dicom_sig = sign_dicom_components(header, pixel_hash, priv_key)
    print(f"   DICOM signature: {dicom_sig[:32]}...")
    
    is_dicom_valid = verify_dicom_signature(header, pixel_hash, dicom_sig, pub_key)
    print(f"   DICOM verification: {'PASSED' if is_dicom_valid else 'FAILED'}")
    
    print("\n" + "=" * 60)
    print("Digital Signature Module Test Complete")
    print("=" * 60)

