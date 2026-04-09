import json
from aes_gcm_utils import encrypt_gcm, decrypt_gcm
from key_manager import get_active_key
from rbac_crypto import allowed_fields

def encrypt_record(record: dict):
    key, key_id = get_active_key()
    encrypted = {}

    for field, value in record.items():
        ct, nonce, tag = encrypt_gcm(value.encode(), key)
        encrypted[field] = {
            "ciphertext": ct.hex(),
            "nonce": nonce.hex(),
            "tag": tag.hex()
        }

    return encrypted, key_id


def decrypt_record(encrypted_record: dict, role: str):
    key, _ = get_active_key()
    visible = allowed_fields(role)
    output = {}

    for field in visible:
        if field in encrypted_record:
            data = encrypted_record[field]
            try:
                plaintext = decrypt_gcm(
                    bytes.fromhex(data["ciphertext"]),
                    key,
                    bytes.fromhex(data["nonce"]),
                    bytes.fromhex(data["tag"])
                )
                output[field] = plaintext.decode()
            except ValueError:
                output[field] = "[ERROR: TAMPERED]"
            except Exception as e:
                output[field] = f"[ERROR: {str(e)}]"

    return output
