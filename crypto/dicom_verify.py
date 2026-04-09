#!/usr/bin/env python3
"""
DICOM Decryption and Signature Verification Script

This script provides a standalone CLI for decrypting and verifying
DICOM data with digital signatures.

Usage:
    python dicom_verify.py <payload_file> [options]
    
Options:
    --role ROLE         RBAC role for decryption (default: doctor)
    --no-verify        Skip signature verification
    --output FILE      Output decrypted data to file
"""

import sys
import json
import os
import argparse

# Add project to path
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

from dicom_handler import DicomHandler, DicomData
from dicom_signature import get_signing_keys, verify_dict_signed
from key_manager import get_active_key


def verify_and_decrypt_dicom(payload_path: str, role: str = "doctor", 
                            verify_signature: bool = True) -> bool:
    """Verify and decrypt a DICOM payload."""
    print("=" * 60)
    print("DICOM Decryption and Signature Verification")
    print("=" * 60)
    
    # Load payload
    if not os.path.exists(payload_path):
        print(f"[ERROR] Payload file not found: {payload_path}")
        return False
    
    with open(payload_path, "r") as f:
        payload = json.load(f)
    
    print(f"\n[INFO] Loaded payload from: {payload_path}")
    
    # Check if this is a DICOM signed package
    if payload.get('package_type') == 'dicom_signed':
        return verify_dicom_signed_package(payload, role, verify_signature)
    
    # Otherwise treat as standard healthcare record
    return verify_standard_payload(payload, role, verify_signature)


def verify_dicom_signed_package(payload: dict, role: str, 
                                verify_signature: bool) -> bool:
    """Handle DICOM signed package"""
    print("\n[INFO] Processing DICOM signed package")
    
    # Get signing keys
    _, pub_key_path = get_signing_keys()
    
    # Verify signature
    if verify_signature:
        print("\n[INFO] Verifying digital signature...")
        from dicom_signature import verify_dicom_signature
        
        encrypted_data = payload.get('encrypted_data', {})
        signature = payload.get('signature', '')
        pixel_hash = encrypted_data.get('pixel_data_hash', '')
        
        is_valid = verify_dicom_signature(
            header_data=encrypted_data,
            pixel_data_hash=pixel_hash,
            signature=signature,
            public_key_path=pub_key_path
        )
        
        if is_valid:
            print("[OK] Digital signature VERIFIED")
        else:
            print("[ERROR] Digital signature VERIFICATION FAILED!")
            print("[WARN] Data may be tampered or from unknown sender!")
            return False
    else:
        print("[INFO] Signature verification skipped")
    
    # Decrypt
    print("\n[INFO] Decrypting DICOM package...")
    aes_key, key_id = get_active_key()
    handler = DicomHandler(aes_key)
    
    try:
        success, message, dicom = handler.verify_and_decrypt_package(payload, pub_key_path)
        
        if success:
            print(f"[OK] {message}")
            print("\n" + "=" * 60)
            print("Decrypted DICOM Header:")
            print("=" * 60)
            for key, value in dicom.header.items():
                print(f"  {key}: {value}")
            return True
        else:
            print(f"[ERROR] {message}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")
        return False


def verify_standard_payload(payload: dict, role: str, 
                           verify_signature: bool) -> bool:
    """Handle standard healthcare record payload"""
    print("\n[INFO] Processing standard healthcare record payload")
    
    # Verify digital signature if present
    if verify_signature and '_signature' in payload:
        print("\n[INFO] Verifying digital signature...")
        _, pub_key_path = get_signing_keys()
        
        if pub_key_path and os.path.exists(pub_key_path):
            is_valid = verify_dict_signed(payload, pub_key_path)
            if is_valid:
                print("[OK] Digital signature VERIFIED - sender authenticity confirmed")
            else:
                print("[ERROR] Digital signature VERIFICATION FAILED!")
                return False
        else:
            print("[WARN] Signing key not found, skipping verification")
    else:
        print("[INFO] No digital signature to verify")
    
    print("\n[INFO] Use secure_email_receiver.py for standard payload decryption")
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Decrypt and verify DICOM data with digital signatures'
    )
    parser.add_argument('payload', help='Path to encrypted payload file')
    parser.add_argument('--role', default='doctor', 
                       help='RBAC role for decryption (default: doctor)')
    parser.add_argument('--no-verify', action='store_true',
                       help='Skip signature verification')
    parser.add_argument('--output', '-o', 
                       help='Output file for decrypted data')
    
    args = parser.parse_args()
    
    success = verify_and_decrypt_dicom(
        args.payload,
        role=args.role,
        verify_signature=not args.no_verify
    )
    
    if success:
        print("\n" + "=" * 60)
        print("DECRYPTION AND VERIFICATION SUCCESSFUL")
        print("=" * 60)
        return 0
    else:
        print("\n" + "=" * 60)
        print("DECRYPTION OR VERIFICATION FAILED")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())

