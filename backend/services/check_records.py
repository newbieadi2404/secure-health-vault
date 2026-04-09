
import json
import os
from aes_gcm_utils import decrypt_gcm
from key_manager import get_active_key

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
PATIENT_RECORDS_FILE = os.path.join(PROJECT_DIR, 'patient_records.json')


def check_file():
    with open(PATIENT_RECORDS_FILE, 'r') as f:
        encrypted_blob = json.load(f)

    key, _ = get_active_key()
    plaintext = decrypt_gcm(
        bytes.fromhex(encrypted_blob['ciphertext']),
        key,
        bytes.fromhex(encrypted_blob['nonce']),
        bytes.fromhex(encrypted_blob['tag'])
    )
    data = json.loads(plaintext.decode('utf-8'))
    print(f"Type: {type(data)}")
    print(f"Data: {data}")


if __name__ == "__main__":
    try:
        check_file()
    except Exception as e:
        print(f"Error: {e}")
