import sys
import os

# Add project root to path so we can import from crypto and root
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Try to load environment variables from .env file
try:
    from dotenv import load_dotenv
    # Use override=True so .env values take priority over system environment variables
    load_dotenv(os.path.join(PROJECT_ROOT, ".env"), override=True)
except ImportError:
    pass

# Add crypto directory to path
CRYPTO_DIR = os.path.join(PROJECT_ROOT, "crypto")
if CRYPTO_DIR not in sys.path:
    sys.path.insert(0, CRYPTO_DIR)

# Add backend/services directory to path
SERVICES_DIR = os.path.join(PROJECT_ROOT, "backend", "services")
if SERVICES_DIR not in sys.path:
    sys.path.insert(0, SERVICES_DIR)

from hybrid_encrypt import encrypt_workflow
from hybrid_decrypt import decrypt_workflow
from verify_audit_log import verify_log
from secure_email_sender import send_encrypted_email_to_all

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python main.py encrypt")
        print("  python main.py encrypt-email <email>")
        print("  python main.py encrypt-email-all")
        print("  python main.py decrypt <role>")
        print("  python main.py verify")
        return

    command = sys.argv[1].lower()

    if command == "encrypt":
        encrypt_workflow()

    elif command == "encrypt-email":
        if len(sys.argv) != 3:
            print("Provide receiver email")
            return
        
        receiver_email = sys.argv[2]
        
        # Basic validation for email
        if "@" not in receiver_email:
            print(f"Error: Invalid email format '{receiver_email}'")
            return
        if "." not in receiver_email.split("@")[-1]:
            print(f"Warning: Email domain for '{receiver_email}' might be incomplete (missing .com, .org, etc.)")
            
        encrypt_workflow(
            send_email=True,
            receiver_email=receiver_email
        )

    elif command == "encrypt-email-all":
        # Encrypt and send to all recipients
        encrypt_workflow(send_email_to_all=True)

    elif command == "decrypt":
        role = sys.argv[2] if len(sys.argv) > 2 else "doctor"
        try:
            decrypt_workflow(role)
        except Exception as e:
            print(f"Decryption failed: {e}")

    elif command == "verify":
        verify_log()

    else:
        print(f"Unknown command '{command}'")

if __name__ == "__main__":
    main()

