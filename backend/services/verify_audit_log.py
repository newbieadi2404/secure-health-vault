import hashlib
import os

# Use project-relative path for audit log
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(PROJECT_DIR, "audit.log")


def verify_log():
    if not os.path.exists(LOG_FILE):
        print("[INFO] No audit log found - starting fresh")
        return
        
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    prev = "0"
    for line in lines:
        parts = line.strip().split("|")
        raw = "|".join(parts[:-1])
        stored_hash = parts[-1]

        if hashlib.sha256(raw.encode()).hexdigest() != stored_hash:
            print("[FAIL] Log tampering detected")
            return

        if parts[-2] != prev:
            print("❌ Hash chain broken")
            return

        prev = stored_hash

    print("[OK] Audit log integrity verified")


if __name__ == "__main__":
    verify_log()

