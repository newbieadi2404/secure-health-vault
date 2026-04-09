import hashlib
import time
import os

# Use project-relative path for audit log
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(PROJECT_DIR, "audit.log")


def _last_hash():
    if not os.path.exists(LOG_FILE):
        return "0"
    with open(LOG_FILE, "r") as f:
        last = f.readlines()[-1]
        return last.strip().split("|")[-1]


def log_event(event_type, message):
    timestamp = int(time.time())
    prev_hash = _last_hash()

    raw = f"{timestamp}|{event_type}|{message}|{prev_hash}"
    curr_hash = hashlib.sha256(raw.encode()).hexdigest()

    with open(LOG_FILE, "a") as f:
        f.write(f"{raw}|{curr_hash}\n")

