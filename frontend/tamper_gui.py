import tkinter as tk
import json
import os
import sys

# Define absolute paths to the files we want to tamper with
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

# Path to secure_payload.json (in crypto folder)
PAYLOAD_FILE = os.path.join(PROJECT_ROOT, "crypto", "secure_payload.json")

# Path to audit.log (in backend/services folder)
AUDIT_LOG = os.path.join(PROJECT_ROOT, "backend", "services", "audit.log")

def log(msg, output=None):
    if output:
        output.insert(tk.END, msg + "\n")
        output.see(tk.END)
    else:
        print(msg)


def tamper_payload(output=None):
    if not os.path.exists(PAYLOAD_FILE):
        log(f"[ERROR] {PAYLOAD_FILE} not found", output)
        return

    with open(PAYLOAD_FILE, "r") as f:
        payload = json.load(f)

    # Payload is a dict of field: {ciphertext, nonce, tag}
    # Pick the first field to tamper with
    fields = list(payload.keys())
    if not fields:
        log("[ERROR] Payload has no fields to tamper with", output)
        return
        
    field_to_tamper = fields[0]
    data = payload[field_to_tamper]
    
    # Flip one hex character in ciphertext
    ct = data["ciphertext"]
    data["ciphertext"] = ct[:-1] + ("0" if ct[-1] != "0" else "1")
    payload[field_to_tamper] = data

    with open(PAYLOAD_FILE, "w") as f:
        json.dump(payload, f, indent=2)

    log(f"[ATTACK] Payload tampered (field '{field_to_tamper}' modified)", output)


def tamper_audit_log(output=None):
    if not os.path.exists(AUDIT_LOG):
        log(f"[ERROR] {AUDIT_LOG} not found", output)
        return

    with open(AUDIT_LOG, "a") as f:
        f.write("\n[ATTACK] Unauthorized audit log modification\n")

    log("[ATTACK] Audit log tampered (hash chain broken)", output)


def reset_system(output=None):
    removed_any = False

    for file in [PAYLOAD_FILE, AUDIT_LOG]:
        if os.path.exists(file):
            os.remove(file)
            removed_any = True

    if removed_any:
        log("[RESET] System state reset (payload & audit log removed)", output)
    else:
        log("[RESET] Nothing to reset (system already clean)", output)


def main():
    root = tk.Tk()
    root.title("Tampering Simulation Console (Red Team)")
    root.geometry("700x480")

    tk.Label(
        root,
        text="Tampering Simulation (For Security Testing Only)",
        font=("Arial", 11, "bold"),
        fg="red"
    ).pack(pady=10)

    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=10)

    output = tk.Text(
        root,
        height=15,
        bg="black",
        fg="orange",
        font=("Consolas", 10)
    )
    output.pack(fill="both", expand=True, padx=10, pady=10)

    tk.Button(
        btn_frame,
        text="Tamper Secure Payload",
        width=25,
        bg="#aa0000",
        fg="white",
        command=lambda: tamper_payload(output)
    ).grid(row=0, column=0, padx=10, pady=5)

    tk.Button(
        btn_frame,
        text="Tamper Audit Log",
        width=25,
        bg="#aa0000",
        fg="white",
        command=lambda: tamper_audit_log(output)
    ).grid(row=0, column=1, padx=10, pady=5)

    tk.Button(
        btn_frame,
        text="Reset System State",
        width=52,
        bg="#003366",
        fg="white",
        command=lambda: reset_system(output)
    ).grid(row=1, column=0, columnspan=2, pady=10)

    root.mainloop()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        action = sys.argv[1]
        if action == "tamper-payload":
            tamper_payload()
        elif action == "tamper-audit":
            tamper_audit_log()
        elif action == "reset":
            reset_system()
        else:
            print(f"Unknown action: {action}")
            sys.exit(1)
    else:
        main()
