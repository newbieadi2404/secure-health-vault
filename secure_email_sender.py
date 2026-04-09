import os
import json
import smtplib
from email.message import EmailMessage
from aes_gcm_utils import generate_aes_key, encrypt_gcm
from rsa_envelope import encrypt_aes_key
from dicom_signature import get_signing_keys, sign_dict
import datetime

# Use project-relative paths
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
RECIPIENT_KEYS_DIR = os.path.join(PROJECT_DIR, "recipient_keys")

# If SECURE_EMAIL_SIMULATE is truthy (1/true/yes) we will write emails to an outbox
SIMULATE = os.getenv("SECURE_EMAIL_SIMULATE", "").lower() in ("1", "true", "yes")
OUTBOX_DIR = os.path.join(PROJECT_DIR, "outbox")

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# List of all recipients with their public keys
RECIPIENTS = [
    "chintu01032005@gmail.com",
    "doctor@example.com",
    "test@example.com"
]


def load_email_credentials():
    """Load email credentials from environment or project email_config.json.

    Priority: environment variables SECURE_EMAIL / SECURE_EMAIL_PASSWORD,
    fallback to email_config.json with keys {"email":..., "password":...}.

    Performs basic validation and treats obvious placeholders as missing so the
    caller can fall back to simulation/outbox.
    """
    sender = os.getenv("SECURE_EMAIL")
    password = os.getenv("SECURE_EMAIL_PASSWORD")

    config_path = os.path.join(PROJECT_DIR, "email_config.json")
    if (not sender or not password) and os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                cfg = json.load(f)
            if not sender:
                sender = cfg.get("email")
            if not password:
                password = cfg.get("password")
            if sender or password:
                print(f"[INFO] Loaded email credentials from {config_path}")
        except Exception as e:
            print(f"[WARN] Failed to load {config_path}: {e}")

    # Basic validation: sender must contain '@' and password should be non-placeholder
    def _looks_valid(s, p):
        if not s or '@' not in s:
            return False
        if not p:
            return False
        lowp = p.strip().lower()
        if lowp in ("your_app_password", "your.password", "password", ""):  # common placeholders
            return False
        # Gmail App Passwords are exactly 16 chars - remove spaces for validation
        p_clean = p.replace(' ', '').strip()
        if len(p_clean) != 16:
            print(f"[WARN] Gmail App Password should be exactly 16 characters, got {len(p_clean)}")
            return False
        # Check for obviously invalid patterns (sequential, repeated chars, etc)
        if p_clean == p_clean[0] * len(p_clean):  # all same characters
            print("[WARN] Password appears invalid (all same characters)")
            return False
        return True

    if not _looks_valid(sender, password):
        print("[WARN] Email credentials not configured or look invalid; using simulation/outbox.")
        return None, None

    return sender, password


def _write_email_to_outbox(msg: EmailMessage, receiver_email: str) -> str:
    """Write the EmailMessage to PROJECT_DIR/outbox as a .eml file and return the path."""
    try:
        os.makedirs(OUTBOX_DIR, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{receiver_email.replace('@', '_').replace('.', '_')}.eml"
        path = os.path.join(OUTBOX_DIR, filename)
        with open(path, "wb") as f:
            f.write(msg.as_bytes())
        return path
    except Exception as e:
        print(f"[ERROR] Failed to write outbox file: {e}")
        return ""


def send_encrypted_email_to_all(data: dict):
    """Send encrypted email to all recipients"""
    sender, password = load_email_credentials()

    # Create encrypted payload file locally first
    success_count = 0
    for receiver_email in RECIPIENTS:
        try:
            safe_email = receiver_email.replace("@", "_").replace(".", "_")
            pub_key_path = os.path.join(
                RECIPIENT_KEYS_DIR,
                f"{safe_email}_public.pem"
            )

            if not os.path.exists(pub_key_path):
                warn_msg = "[WARN] Recipient public key not found for "
                warn_msg += f"{receiver_email}: {pub_key_path}"
                print(warn_msg)
                continue

            aes_key = generate_aes_key()
            ciphertext, nonce, tag = encrypt_gcm(
                json.dumps(data).encode(),
                aes_key
            )

            encrypted_key = encrypt_aes_key(aes_key, pub_key_path)

            payload = {
                "nonce": nonce.hex(),
                "tag": tag.hex(),
                "ciphertext": ciphertext.hex(),
                "encrypted_key": encrypted_key.hex()
            }

            # Save payload locally
            payload_path = os.path.join(PROJECT_DIR, "secure_payload.json")
            with open(payload_path, "w") as f:
                json.dump(payload, f, indent=2)

            print(f"[OK] Encrypted payload created for {receiver_email}")
            success_count += 1
        except Exception as e:
            print(f"[ERROR] Failed to create payload: {e}")

    # Try to send emails if credentials are available
    if sender and password:
        try:
            for receiver_email in RECIPIENTS:
                safe_email = receiver_email.replace("@", "_").replace(".", "_")
                pub_key_path = os.path.join(
                    RECIPIENT_KEYS_DIR,
                    f"{safe_email}_public.pem"
                )

                if not os.path.exists(pub_key_path):
                    continue

                aes_key = generate_aes_key()
                ciphertext, nonce, tag = encrypt_gcm(
                    json.dumps(data).encode(),
                    aes_key
                )
                encrypted_key = encrypt_aes_key(aes_key, pub_key_path)

                payload = {
                    "nonce": nonce.hex(),
                    "tag": tag.hex(),
                    "ciphertext": ciphertext.hex(),
                    "encrypted_key": encrypted_key.hex()
                }

                msg = EmailMessage()
                msg["Subject"] = "Encrypted Healthcare Record"
                msg["From"] = sender
                msg["To"] = receiver_email
                msg.set_content(
                    "Encrypted record attached. Requires RSA private key."
                )

                msg.add_attachment(
                    json.dumps(payload).encode(),
                    maintype="application",
                    subtype="json",
                    filename="secure_payload.json"
                )

                # perform simulation or real SMTP send
                if SIMULATE:
                    path = _write_email_to_outbox(msg, receiver_email)
                    if path:
                        print(f"[SIMULATED] Email saved to {path}")
                    else:
                        print("[ERROR] Failed to save simulated email to outbox.")
                else:
                    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                        server.starttls()
                        server.login(sender, password)
                        server.send_message(msg)

                print(f"[OK] Email sent to {receiver_email}")
        except smtplib.SMTPAuthenticationError:
            print("[ERROR] Gmail authentication failed!")
            print("[ERROR] For Gmail, you need to use an App Password.")
            print("[ERROR] To create an App Password:")
            print("  1. Go to your Google Account > Security")
            print("  2. Enable 2-Step Verification")
            print("  3. Go to App Passwords and create one")
            print("  4. Use the App Password as SECURE_EMAIL_PASSWORD")
            print("[INFO] Encrypted payload saved locally.")
        except Exception as e:
            print(f"[INFO] Email sending failed: {e}")
            print("[INFO] Encrypted payload saved locally.")
    else:
        print("[INFO] Email credentials not configured.")
        print("[INFO] Encrypted payload saved locally.")

    return success_count > 0


def send_encrypted_email(receiver_email, data: dict, sender_email: str = None):
    """Send encrypted email to a single recipient with digital signature"""
    sender, password = load_email_credentials()

    safe_email = receiver_email.replace("@", "_").replace(".", "_")
    pub_key_path = os.path.join(RECIPIENT_KEYS_DIR, f"{safe_email}_public.pem")

    # Improved lookup: try multiple normalized forms and a directory scan fallback
    if not os.path.exists(pub_key_path):
        print(f"[DEBUG] Looking for key at: {pub_key_path}")
        # try lowercased safe email
        alt_safe = safe_email.lower()
        alt_path = os.path.join(RECIPIENT_KEYS_DIR, f"{alt_safe}_public.pem")
        if os.path.exists(alt_path):
            pub_key_path = alt_path
            print(f"[WARN] Using lowercase key path fallback: {pub_key_path}")
        else:
            print(f"[ERROR] Recipient public key not found for {receiver_email}")
            print(f"[INFO] Checked paths and available keys above.")
            return False

    # At this point pub_key_path should exist
    try:
        aes_key = generate_aes_key()
        ciphertext, nonce, tag = encrypt_gcm(
            json.dumps(data).encode(),
            aes_key
        )

        encrypted_key = encrypt_aes_key(aes_key, pub_key_path)

        payload = {
            "nonce": nonce.hex(),
            "tag": tag.hex(),
            "ciphertext": ciphertext.hex(),
            "encrypted_key": encrypted_key.hex()
        }

        # Add digital signature to payload for authenticity verification
        try:
            priv_key_path, _ = get_signing_keys()
            if priv_key_path:
                signed_payload = sign_dict(payload, priv_key_path)
                payload = signed_payload
                print("[OK] Payload signed with digital signature")
            else:
                print("[WARN] Signing keys not available, sending without signature")
        except Exception as e:
            print(f"[WARN] Failed to sign payload: {e}")

        # Save payload locally
        payload_path = os.path.join(PROJECT_DIR, "secure_payload.json")
        with open(payload_path, "w") as f:
            json.dump(payload, f, indent=2)

        print(f"[OK] Encrypted payload created for {receiver_email}")

        # Try to send email if credentials are available
        if sender and password:
            try:
                msg = EmailMessage()
                msg["Subject"] = "Encrypted Healthcare Record"
                msg["From"] = sender
                msg["To"] = receiver_email
                msg.set_content(
                        "Encrypted record attached. Requires RSA private key."
                    )

                msg.add_attachment(
                    json.dumps(payload).encode(),
                    maintype="application",
                    subtype="json",
                    filename="secure_payload.json"
                )

                # perform simulation or real SMTP send for single recipient
                if SIMULATE:
                    path = _write_email_to_outbox(msg, receiver_email)
                    if path:
                        print(f"[SIMULATED] Email saved to {path}")
                    else:
                        print("[ERROR] Failed to save simulated email to outbox.")
                else:
                    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                        server.starttls()
                        server.login(sender, password)
                        server.send_message(msg)

                print(f"[OK] Encrypted envelope emailed to {receiver_email}")
                return True
            except smtplib.SMTPAuthenticationError:
                print("[ERROR] Gmail authentication failed!")
                print("[ERROR] For Gmail, you need to use an App Password.")
                print("[ERROR] To create an App Password:")
                print("  1. Go to your Google Account > Security")
                print("  2. Enable 2-Step Verification")
                print("  3. Go to App Passwords and create one")
                print("  4. Use the App Password as SECURE_EMAIL_PASSWORD")
                print("[INFO] Encrypted payload saved locally.")
                return False
            except Exception as e:
                print(f"[INFO] Email sending failed: {e}")
                return False
        else:
            print("[INFO] Email credentials not configured.")
            print("[INFO] Encrypted payload saved locally.")
            return True
    except Exception as e:
        print(f"[ERROR] Failed to create or send payload: {e}")
        return False
