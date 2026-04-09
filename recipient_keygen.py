from Crypto.PublicKey import RSA
import os

def generate_recipient_keys(email):
    os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), "recipient_keys"), exist_ok=True)

    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    safe_email = email.replace("@", "_").replace(".", "_")

    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), f"recipient_keys/{safe_email}_private.pem"), "wb") as f:
        f.write(private_key)

    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), f"recipient_keys/{safe_email}_public.pem"), "wb") as f:
        f.write(public_key)

    print(f"[OK] RSA keys generated for {email}")

if __name__ == "__main__":
    generate_recipient_keys("chintu01032005@gmail.com")

