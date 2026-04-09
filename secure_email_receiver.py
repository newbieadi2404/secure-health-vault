import sys
import json
import os
import base64
import re
from aes_gcm_utils import decrypt_gcm
from rsa_envelope import decrypt_aes_key
from secure_record import decrypt_record
from dicom_signature import verify_dict_signed, get_signing_keys


# Project directory
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
RECIPIENT_KEYS_DIR = os.path.join(PROJECT_DIR, "recipient_keys")

def extract_payload_from_eml(eml_path):
    """Extract JSON payload from an .eml email file"""
    try:
        with open(eml_path, 'r') as f:
            eml_content = f.read()
        
        # Extract JSON payload from email (base64 encoded)
        match = re.search(
            r'Content-Type: application/json.*?Content-Transfer-Encoding: base64\s*\n(.*?)(?=--==)',
            eml_content, 
            re.DOTALL
        )
        if match:
            json_b64 = match.group(1).strip()
            json_bytes = base64.b64decode(json_b64)
            return json.loads(json_bytes)
        else:
            print("[ERROR] Could not extract JSON payload from email")
            return None
    except Exception as e:
        print(f"[ERROR] Failed to parse email: {e}")
        return None


def decrypt_received_payload(payload_path, receiver_email, role="doctor", verify_signature_flag=True):
    """Decrypt received payload and optionally verify digital signature.
    
    Args:
        payload_path: Path to payload file or email
        receiver_email: Receiver's email for key lookup
        role: RBAC role for decryption
        verify_signature_flag: Whether to verify digital signature
    
    Returns:
        tuple: (success: bool, message: str, decrypted_data: dict or None)
    """
    safe_email = receiver_email.replace("@", "_").replace(".", "_")
    priv_key_path = os.path.join(RECIPIENT_KEYS_DIR, f"{safe_email}_private.pem")

    # Check if private key exists
    if not os.path.exists(priv_key_path):
        msg = f"Private key not found: {priv_key_path}"
        print(f"[ERROR] {msg}")
        return False, msg, None

    # Determine payload source
    payload = None
    if payload_path.endswith('.eml'):
        # Extract from email file
        if not os.path.exists(payload_path):
            msg = f"Email file not found: {payload_path}"
            print(f"[ERROR] {msg}")
            return False, msg, None
        else:
            payload = extract_payload_from_eml(payload_path)
    else:
        # Load from JSON file
        if not os.path.exists(payload_path):
            msg = f"Payload file not found: {payload_path}"
            print(f"[ERROR] {msg}")
            return False, msg, None
        else:
            try:
                with open(payload_path, "r") as f:
                    payload = json.load(f)
            except json.JSONDecodeError:
                msg = "The file is not a valid JSON payload. Please ensure you are uploading the original encrypted file."
                print(f"[ERROR] {msg}")
                return False, msg, None

    if payload is None:
        msg = "No payload found to decrypt"
        print(f"[ERROR] {msg}")
        return False, msg, None

    # Verify digital signature if present and requested
    signature_verified = False
    if verify_signature_flag and '_signature' in payload:
        print("\n[INFO] Digital signature found, verifying...")
        try:
            _, pub_key_path = get_signing_keys()
            if pub_key_path and os.path.exists(pub_key_path):
                signature_verified = verify_dict_signed(payload, pub_key_path)
                if signature_verified:
                    print("[OK] Digital signature VERIFIED - sender authenticity confirmed")
                else:
                    print("[ERROR] Digital signature VERIFICATION FAILED!")
            else:
                print("[WARN] Signing public key not found, skipping signature verification")
        except Exception as e:
            print(f"[WARN] Signature verification error: {e}")

    # Decrypt AES envelope key using RSA private key
    try:
        aes_key = decrypt_aes_key(
            bytes.fromhex(payload["encrypted_key"]),
            priv_key_path
        )
    except Exception as e:
        msg = "Failed to decrypt AES key: Incorrect decryption. This usually means the payload was encrypted with a different recipient's public key."
        print(f"[ERROR] {msg}")
        return False, msg, None

    # Decrypt email envelope (integrity verified here)
    try:
        plaintext = decrypt_gcm(
            bytes.fromhex(payload["ciphertext"]),
            aes_key,
            bytes.fromhex(payload["nonce"]),
            bytes.fromhex(payload["tag"])
        )
    except Exception as e:
        msg = f"Failed to decrypt payload: {e}"
        print(f"[ERROR] {msg}")
        return False, msg, None

    print("\n[OK] Email integrity verified.")

    # Check if this is a medical image package
    try:
        decrypted_data = json.loads(plaintext.decode())
        
        if isinstance(decrypted_data, dict) and decrypted_data.get('package_type') == 'medical_image':
            return True, "Medical Image Package Decrypted Successfully", decrypted_data
            
        # Otherwise, treat as standard RBAC-encrypted data
        rbac_encrypted_record = decrypted_data
    except json.JSONDecodeError:
        msg = "Decrypted payload is not valid JSON"
        print(f"[ERROR] {msg}")
        return False, msg, None

    # Apply RBAC decryption
    final_data = decrypt_record(rbac_encrypted_record, role=role)

    print(f"\n[OK] Decrypted data (RBAC enforced for role='{role}'):")
    print(json.dumps(final_data, indent=2))
    return True, f"Data decrypted successfully (Role: {role})", final_data


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        print("Usage: python secure_email_receiver.py <payload.json|email.eml> <email> [role]")
        sys.exit(1)

    payload = sys.argv[1]
    email = sys.argv[2]
    role = sys.argv[3] if len(sys.argv) == 4 else "doctor"

    success = decrypt_received_payload(payload, email, role)
    sys.exit(0 if success else 1)

