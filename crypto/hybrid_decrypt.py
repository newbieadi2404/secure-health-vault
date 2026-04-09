import json
import os
from secure_record import decrypt_record
from audit_logger import log_event

# File paths
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
ENCRYPTED_FILE = os.path.join(PROJECT_DIR, "secure_payload.json")

def decrypt_workflow(role="doctor"):
    if not os.path.exists(ENCRYPTED_FILE):
        print(f"Error: Encrypted file not found at {ENCRYPTED_FILE}")
        return
        
    with open(ENCRYPTED_FILE, "r") as f:
        encrypted_record = json.load(f)

    decrypted = decrypt_record(encrypted_record, role)

    print("\nDecrypted Record (RBAC enforced):")
    for k, v in decrypted.items():
        print(f"{k}: {v}")

    log_event("DECRYPT", f"Record decrypted for role={role}")

if __name__ == "__main__":
    decrypt_workflow()
