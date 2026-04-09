import json
import os
from secure_record import encrypt_record
from secure_email_sender import send_encrypted_email, send_encrypted_email_to_all
from audit_logger import log_event

# File paths
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
ENCRYPTED_FILE = os.path.join(PROJECT_DIR, "secure_payload.json")


def encrypt_workflow(send_email=False, receiver_email=None, send_email_to_all=False):
    record = {
        "patient_id": "P1023",
        "diagnosis": "Hypertension",
        "prescription": "Amlodipine",
        "lab_results": "BP 150/90"
    }

    encrypted_record, key_id = encrypt_record(record)
    
    # Save encrypted record to file for decryption
    with open(ENCRYPTED_FILE, "w") as f:
        json.dump(encrypted_record, f, indent=2)
    
    log_event("ENCRYPT", f"Encrypted using key {key_id}")

    if send_email and receiver_email:
        send_encrypted_email(receiver_email, encrypted_record)
    
    if send_email_to_all:
        send_encrypted_email_to_all(encrypted_record)

    print("Healthcare record encrypted with hybrid envelope encryption.")
    print(f"Encrypted data saved to {ENCRYPTED_FILE}")

