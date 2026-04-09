import json
import os
import time
from aes_gcm_utils import generate_aes_key

# Use project-relative absolute path for key storage
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(PROJECT_DIR, "keys")
KEY_STORE = os.path.join(KEYS_DIR, "aes_keys.json")
KEY_TTL_SECONDS = 60 * 60 * 24 * 30  # 30 days


def _load_keys():
    if not os.path.exists(KEY_STORE):
        return []
    with open(KEY_STORE, "r") as f:
        return json.load(f)


def _save_keys(keys):
    os.makedirs(os.path.dirname(KEY_STORE), exist_ok=True)
    with open(KEY_STORE, "w") as f:
        json.dump(keys, f, indent=2)


def get_active_key():
    keys = _load_keys()
    now = int(time.time())

    for key in keys:
        if key["expires_at"] > now:
            return bytes.fromhex(key["key"]), key["key_id"]

    return rotate_key()


def get_key_by_id(key_id):
    """Retrieve a specific key by its ID from the store."""
    keys = _load_keys()
    for key in keys:
        if key["key_id"] == key_id:
            return bytes.fromhex(key["key"])
    return None


def rotate_key():
    keys = _load_keys()
    now = int(time.time())

    new_key = generate_aes_key()
    entry = {
        "key_id": f"aes_{now}",
        "key": new_key.hex(),
        "created_at": now,
        "expires_at": now + KEY_TTL_SECONDS
    }

    keys.append(entry)
    _save_keys(keys)

    return new_key, entry["key_id"]
