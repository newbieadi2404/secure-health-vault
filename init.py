#!/usr/bin/env python3
"""
Initialization script for Healthcare Crypto System
Generates required RSA keys for encryption/decryption
"""
import os
import json
from Crypto.PublicKey import RSA

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_DIR = os.path.join(PROJECT_DIR, "keys")
RECIPIENT_KEYS_DIR = os.path.join(PROJECT_DIR, "recipient_keys")

# Default recipients with their emails
RECIPIENTS = [
    "chintu01032005@gmail.com",
    "doctor@example.com",
    "doctor2@example.com",
    "test@example.com"
]


def generate_system_keys():
    """Generate system RSA key pair for AES key wrapping"""
    os.makedirs(KEY_DIR, exist_ok=True)
    
    priv_path = os.path.join(KEY_DIR, "private.pem")
    pub_path = os.path.join(KEY_DIR, "public.pem")
    
    # Check if keys already exist
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        print(f"[INFO] System keys exist in {KEY_DIR}")
        return
    
    print("[INFO] Generating system RSA-2048 keys...")
    key = RSA.generate(2048)
    
    with open(priv_path, "wb") as f:
        f.write(key.export_key())
    
    with open(pub_path, "wb") as f:
        f.write(key.publickey().export_key())
    
    print(f"[OK] System keys generated in {KEY_DIR}")


def generate_recipient_keys():
    """Generate RSA key pairs for all recipients"""
    os.makedirs(RECIPIENT_KEYS_DIR, exist_ok=True)
    
    for email in RECIPIENTS:
        safe_email = email.split("@")[0]
        p_priv = os.path.join(RECIPIENT_KEYS_DIR, f"{safe_email}_private.pem")
        p_pub = os.path.join(RECIPIENT_KEYS_DIR, f"{safe_email}_public.pem")
        
        if os.path.exists(p_priv) and os.path.exists(p_pub):
            print(f"[INFO] Keys exist for {email}")
            continue
        
        print(f"[INFO] Generating RSA-2048 keys for {email}...")
        key = RSA.generate(2048)
        
        with open(p_priv, "wb") as f:
            f.write(key.export_key())
        
        with open(p_pub, "wb") as f:
            f.write(key.publickey().export_key())
        
        print(f"[OK] Keys generated for {email}")


def initialize_aes_keys():
    """Initialize AES keys storage"""
    os.makedirs(KEY_DIR, exist_ok=True)
    aes_keys_file = os.path.join(KEY_DIR, "aes_keys.json")
    
    if os.path.exists(aes_keys_file):
        print("[INFO] AES keys already initialized")
        return
    
    # Create empty AES keys file
    with open(aes_keys_file, "w") as f:
        json.dump([], f)
    
    print("[OK] AES keys storage initialized")


def main():
    print("=" * 60)
    print("🔐 Healthcare Crypto System - Initialization")
    print("=" * 60)
    
    generate_system_keys()
    generate_recipient_keys()
    initialize_aes_keys()
    
    print("=" * 60)
    print("[OK] System initialized successfully!")
    print("=" * 60)
    print("\nYou can now run the web interface:")
    print("  python app.py")
    print("\nOr use the CLI:")
    print("  python main.py encrypt")
    print("  python main.py decrypt doctor")


if __name__ == "__main__":
    main()

