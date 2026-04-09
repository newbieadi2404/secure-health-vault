import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading

PROJECT_PYTHON = "python"


def run_command(cmd, output_box):
    output_box.insert(tk.END, f"\n>>> {' '.join(cmd)}\n")
    output_box.see(tk.END)

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        for line in process.stdout:
            output_box.insert(tk.END, line)
            output_box.see(tk.END)

        for line in process.stderr:
            output_box.insert(tk.END, line)
            output_box.see(tk.END)

    except Exception as e:
        output_box.insert(tk.END, f"ERROR: {e}\n")


def run_async(cmd, output_box):
    threading.Thread(
        target=run_command,
        args=(cmd, output_box),
        daemon=True
    ).start()


def encrypt(output):
    run_async([PROJECT_PYTHON, "main.py", "encrypt"], output)


def decrypt(output):
    run_async([PROJECT_PYTHON, "main.py", "decrypt"], output)


def verify_audit(output):
    run_async([PROJECT_PYTHON, "main.py", "verify"], output)


def encrypt_email(output, email_entry):
    email = email_entry.get().strip()
    if not email:
        messagebox.showerror("Error", "Enter recipient email")
        return
    run_async([PROJECT_PYTHON, "main.py", "encrypt-email", email], output)


def receive_email(output, email_entry, role_var):
    email = email_entry.get().strip()
    role = role_var.get()
    if not email:
        messagebox.showerror("Error", "Enter recipient email")
        return
    run_async(
        [PROJECT_PYTHON, "secure_email_receiver.py", "secure_payload.json", email, role],
        output
    )


def main():
    root = tk.Tk()
    root.title("Secure Healthcare Crypto System")
    root.geometry("900x650")

    # Instruction panel
    instructions = (
        "STEP 1: Encrypt healthcare data\n"
        "STEP 2: Decrypt locally (RBAC enforced)\n"
        "STEP 3: Send encrypted email\n"
        "STEP 4: Download secure_payload.json from email\n"
        "STEP 5: Receive & verify with role\n"
        "STEP 6: Verify audit log\n"
        "STEP 7: Perform tamper tests\n"
    )

    tk.Label(root, text=instructions, justify="left", font=("Arial", 10, "bold")).pack(pady=10)

    # Email input
    email_frame = tk.Frame(root)
    email_frame.pack()

    tk.Label(email_frame, text="Recipient Email:").grid(row=0, column=0, padx=5)
    email_entry = tk.Entry(email_frame, width=40)
    email_entry.grid(row=0, column=1, padx=5)

    # Role selector
    tk.Label(email_frame, text="Role:").grid(row=0, column=2, padx=5)
    role_var = tk.StringVar(value="doctor")
    ttk.Combobox(
        email_frame,
        textvariable=role_var,
        values=["doctor", "nurse", "admin"],
        width=10,
        state="readonly"
    ).grid(row=0, column=3, padx=5)

    # Buttons
    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=10)

    tk.Button(btn_frame, text="Encrypt", width=18,
              command=lambda: encrypt(output_box)).grid(row=0, column=0, padx=5, pady=5)

    tk.Button(btn_frame, text="Decrypt", width=18,
              command=lambda: decrypt(output_box)).grid(row=0, column=1, padx=5, pady=5)

    tk.Button(btn_frame, text="Send Secure Email", width=18,
              command=lambda: encrypt_email(output_box, email_entry)).grid(row=0, column=2, padx=5, pady=5)

    tk.Button(btn_frame, text="Receive & Verify Email", width=18,
              command=lambda: receive_email(output_box, email_entry, role_var)).grid(row=1, column=0, padx=5, pady=5)

    tk.Button(btn_frame, text="Verify Audit Log", width=18,
              command=lambda: verify_audit(output_box)).grid(row=1, column=1, padx=5, pady=5)

    # Output console
    output_box = tk.Text(root, height=20, bg="black", fg="lime", font=("Consolas", 10))
    output_box.pack(fill="both", expand=True, padx=10, pady=10)

    root.mainloop()


if __name__ == "__main__":
    main()
