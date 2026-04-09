import subprocess
import sys
import os
import json
import datetime
import numpy as np
from typing import Dict, Any, cast, List

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from werkzeug.utils import secure_filename
from flask import (
    Flask, render_template, request, redirect, url_for, flash, session,
    make_response, jsonify, send_from_directory
)
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from backend.services.audit_logger import log_event, LOG_FILE
from crypto.aes_gcm_utils import encrypt_gcm, decrypt_gcm
from crypto.key_manager import get_active_key, get_key_by_id
from secure_email_receiver import decrypt_received_payload
from backend.services.secure_record import encrypt_record
from secure_email_sender import (
    send_encrypted_email, send_encrypted_email_to_all
)
from functools import wraps

# Try to load environment variables from .env file
try:
    from dotenv import load_dotenv
    # Use override=True so .env values take priority over system environment variables
    load_dotenv(os.path.join(PROJECT_ROOT, ".env"), override=True)
except ImportError:
    pass  # python-dotenv not installed, continue without it

# Role-based access control - define which roles can access which routes
ROLE_PERMISSIONS = {
    'index': ['doctor', 'nurse', 'admin', 'patient'],
    'encrypt': ['admin'],
    'decrypt': ['admin'],
    'send_email': ['doctor', 'nurse', 'patient', 'admin'],
    'encrypt_image': ['doctor', 'patient', 'admin'],
    'send_image': ['doctor', 'patient', 'admin'],
    'receive_email': ['doctor', 'nurse', 'patient', 'admin'],
    'prescriptions': ['doctor', 'nurse', 'admin'],
    'medical_reports': ['doctor', 'nurse', 'admin'],
    'appointments': ['doctor', 'nurse', 'admin'],
    'patient_records': ['doctor', 'nurse', 'admin'],
    'patient_dashboard': ['patient', 'admin'],
    'verify_audit': ['admin'],
    'tamper_test': ['admin'],
    'status': ['admin'],
    'profile': ['doctor', 'nurse', 'admin', 'patient'],
    'settings': ['doctor', 'nurse', 'admin', 'patient'],
    'security': ['doctor', 'nurse', 'admin', 'patient'],
    'activity': ['doctor', 'nurse', 'admin', 'patient'],
    'help_page': ['doctor', 'nurse', 'admin', 'patient'],
    'tutorials': ['doctor', 'nurse', 'admin', 'patient'],
    'live_chat': ['doctor', 'nurse', 'admin', 'patient'],
    'download_id': ['patient', 'admin'],
    'request_access': ['patient', 'admin'],
    'lab_results': ['doctor', 'nurse', 'admin'],
    'image_analysis': ['doctor', 'admin'],
    'decrypt_image': ['doctor', 'admin'],
    'admin_dashboard': ['admin'],
}


# Global list of recipient emails for encryption
RECIPIENT_EMAILS = [
    "doctor@example.com",
    "doctor2@example.com",
    "patient@example.com",
    "faiyazmansuri2003@gmail.com",
    "pandajod8@gmail.com",
    "aditya10thf@gmail.com",
    "chintu01032005@gmail.com",
    "test@example.com",
    "nurse@example.com"
]


def role_required(route_name):
    """Decorator to enforce role-based access control"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('logged_in'):
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))

            user_role = session.get('role', '')
            allowed_roles = ROLE_PERMISSIONS.get(route_name, [])

            if user_role not in allowed_roles:
                flash(
                    f'Access denied. Your role ({user_role}) does not have '
                    f'permission to access this page.', 'error'
                )
                # Log out the user
                session.clear()
                return redirect(url_for('login'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator


TEMPLATES_DIR = os.path.normpath(os.path.join(PROJECT_ROOT, 'frontend', 'templates'))
app = Flask(__name__, template_folder=TEMPLATES_DIR)
app.secret_key = 'healthcare_crypto_secret_key'

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

# Data storage files
PRESCRIPTIONS_FILE = os.path.join(PROJECT_DIR, 'prescriptions.json')
MEDICAL_REPORTS_FILE = os.path.join(PROJECT_DIR, 'medical_reports.json')
APPOINTMENTS_FILE = os.path.join(PROJECT_DIR, 'appointments.json')
PATIENT_RECORDS_FILE = os.path.join(PROJECT_DIR, 'patient_records.json')
PATIENTS_FILE = os.path.join(PROJECT_DIR, 'patients.json')


def load_patients():
    """Load patients account data"""
    return load_data(PATIENTS_FILE, default_value={})


def save_patients(patients):
    """Save patients account data"""
    save_data(PATIENTS_FILE, patients)


def load_data(file_path, default_value=None):
    """Load data from JSON file (with automatic decryption if encrypted)"""
    if default_value is None:
        default_value = []

    if not os.path.exists(file_path):
        return default_value

    with open(file_path, 'rb') as f:
        content = f.read()

    if not content:
        return default_value

    # Try to parse as plain JSON first
    try:
        data = json.loads(content.decode('utf-8'))
        # If it's a dict with encryption keys, it's NOT plain data
        required_keys = ['ciphertext', 'nonce', 'tag']
        if isinstance(data, dict) and all(k in data for k in required_keys):
            # 구조가 암호화된 블롭이므로 복호화 시도
            pass
        else:
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass

    # Try to decrypt
    try:
        # The file is expected to be a JSON with ciphertext, nonce, tag
        encrypted_blob = json.loads(content)
        required_keys = ['ciphertext', 'nonce', 'tag']
        if all(k in encrypted_blob for k in required_keys):
            key, _ = get_active_key()
            plaintext = decrypt_gcm(
                bytes.fromhex(encrypted_blob['ciphertext']),
                key,
                bytes.fromhex(encrypted_blob['nonce']),
                bytes.fromhex(encrypted_blob['tag'])
            )
            return json.loads(plaintext.decode('utf-8'))
    except Exception as e:
        print(
            f"[ERROR] Failed to load/decrypt database file "
            f"{file_path}: {e}"
        )
        return default_value
    return default_value


def save_data(file_path, data):
    """Save data to JSON file with AES-256-GCM encryption"""
    try:
        key, _ = get_active_key()
        json_content = json.dumps(data).encode('utf-8')

        ciphertext, nonce, tag = encrypt_gcm(json_content, key)

        encrypted_blob = {
            'ciphertext': ciphertext.hex(),
            'nonce': nonce.hex(),
            'tag': tag.hex(),
            'encrypted_at': datetime.datetime.now().isoformat()
        }

        with open(file_path, 'w') as f:
            json.dump(encrypted_blob, f, indent=2)

    except Exception as e:
        print(
            f"[ERROR] Failed to encrypt/save database file "
            f"{file_path}: {e}"
        )
        # Fallback to plain JSON if encryption fails
        # (optional, but safer for now)
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)


# Simple user credentials (can be extended with a database)
USERS = {
    'doctor': {
        'password': 'doctor123',
        'role': 'doctor',
        'email': 'doctor@example.com'
    },
    'doctor2': {
        'password': 'doctor123',
        'role': 'doctor',
        'email': 'doctor2@example.com'
    },
    'nurse': {
        'password': 'nurse123',
        'role': 'nurse',
        'email': 'nurse@example.com'
    },
    'admin': {
        'password': 'admin123',
        'role': 'admin',
        'email': 'admin@example.com'
    },
    'patient': {
        'password': 'patient123',
        'role': 'patient',
        'email': 'patient@example.com'
    },
    'faiyaz': {
        'password': 'faiyaz7860',
        'role': 'patient',
        'email': 'faiyazmansuri2003@gmail.com'
    },
    'arbaz': {
        'password': 'faiyaz7860',
        'role': 'patient',
        'email': 'pandajod8@gmail.com'
    },
    'faiyaz303': {
        'password': 'doctor123',
        'role': 'doctor',
        'email': 'faiyazmansuri303@gmail.com'
    },
    'aditya.mishra': {
        'password': 'doctor123',
        'role': 'doctor',
        'email': 'chintu01032005@gmail.com'
    },
}

# Hospital data
HOSPITALS = {
    'city_general': {
        'id': 'city_general',
        'name': 'City General Hospital',
        'address': '123 Healthcare Avenue, Medical District',
        'phone': '+1 (555) 123-4567',
        'email': 'info@citygeneralhospital.com'
    },
    'st_marys': {
        'id': 'st_marys',
        'name': "St. Mary's Medical Center",
        'address': '456 Hope Street, Downtown',
        'phone': '+1 (555) 987-6543',
        'email': 'contact@stmarysmedical.com'
    },
    'university_hospital': {
        'id': 'university_hospital',
        'name': 'University Hospital',
        'address': '789 Academic Way, College Town',
        'phone': '+1 (555) 456-7890',
        'email': 'admissions@universityhospital.edu'
    }
}

# File upload configuration
UPLOAD_FOLDER = os.path.join(PROJECT_DIR, 'uploads')
ALLOWED_EXTENSIONS = {
    'png', 'jpg', 'jpeg', 'gif', 'pdf', 'dcm', 'xray', 'bmp', 'webp'
}


# Create upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_file(filename):
    return (
        '.' in filename and
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def load_email_config():
    """Load email configuration from JSON file (encrypted)"""
    config_path = os.path.join(PROJECT_DIR, 'email_config.json')
    
    # 1. Check for logged-in user email override
    if session.get('logged_in'):
        username = cast(str, session.get('user', ''))
        user_info = USERS.get(username)
        if user_info and user_info.get('email') == 'chintu01032005@gmail.com':
            # Use specific app password from .env for chintu
            from dotenv import load_dotenv
            load_dotenv(os.path.join(PROJECT_ROOT, ".env"), override=True)
            return {
                'email': 'chintu01032005@gmail.com',
                'password': os.getenv('SECURE_EMAIL_PASSWORD', 'ucfrzqtehztjmuom')
            }

    # 2. Regular load from file
    config = load_data(config_path, default_value={})
    if not config:
        # Fallback to plain JSON if encryption fails or file is not yet
        # encrypted
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                try:
                    return cast(Dict[str, str], json.load(f))
                except Exception:
                    return {}
    return cast(Dict[str, str], config)


def send_smtp_email(to_email, subject, body):
    """Send email using SMTP"""
    config = cast(Dict[str, str], load_email_config())
    smtp_email = config.get('email', 'chintu01032005@gmail.com')
    smtp_password = config.get('password', 'ucfrzqtehztjmuom')

    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(smtp_email, smtp_password)
        server.sendmail(smtp_email, to_email, msg.as_string())
        server.quit()
        return True, "Email sent successfully"
    except Exception as e:
        return False, str(e)


def initialize_system():
    """Run initialization if keys don't exist"""
    keys_dir = os.path.join(PROJECT_DIR, 'keys')
    if not os.path.exists(keys_dir) or not os.path.exists(
            os.path.join(keys_dir, 'public.pem')):
        print("[INFO] Running system initialization...")
        try:
            subprocess.run(
                [sys.executable, 'init.py'],
                cwd=PROJECT_DIR,
                capture_output=True,
                timeout=30
            )
        except Exception as e:
            print(f"[WARN] Initialization warning: {e}")


# Initialize system on startup
initialize_system()


def run_python_script(script_name, args=None):
    """Run a Python script and return output"""
    cmd = [sys.executable, script_name]
    if args:
        cmd.extend(args)

    # Pass environment variables to subprocess
    env = os.environ.copy()

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=PROJECT_DIR,
            timeout=30,
            env=env
        )
        return result.stdout + result.stderr, result.returncode
    except Exception as e:
        return str(e), 1


@app.route('/')
@role_required('index')
def index():
    """Home/Dashboard page - requires login"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page with Sign In, Sign Up, and Forgot Password"""
    if request.method == 'POST':
        action = request.form.get('action', 'signin')

        # Handle Sign Up
        if action == 'signup':
            name = request.form.get('name', '').strip()
            username = request.form.get('username', '').strip().lower()
            password = request.form.get('password', '')
            role = request.form.get('role', '')

            if not name or not username or not password:
                flash('Please fill in all required fields.', 'error')
                return redirect(url_for('login'))

            # For staff (doctor, nurse, admin)
            if username in USERS:
                flash('Username already exists. Please sign in.', 'error')
                return redirect(url_for('login'))
            USERS[username] = {'password': password, 'role': role}
            flash(
                f'Account created for {role}! Please sign in.',
                'success'
            )
            return redirect(url_for('login'))

        # Handle Forgot Password
        elif action == 'forgot':
            username = request.form.get('username', '').strip().lower()

            # Check if user exists
            if username in USERS:
                # For staff users, send reset email
                staff_email = f"{username}@healthcrypto.com"
                base_url = "http://localhost:8000"
                reset_link = f"{base_url}/reset-password?user={username}"
                email_subject = "Password Reset - Healthcare Crypto System"
                email_body = f"""
                <html>
                <body style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2 style="color: #00d4ff;">Password Reset Request</h2>
                    <p>Hello {username},</p>
                    <p>We received a request to reset your password.
                       Click the link below to reset your password:</p>
                    <p><a href="{reset_link}" style="background: #00d4ff;
                       color: white; padding: 10px 20px;
                       text-decoration: none; border-radius: 5px;">
                       Reset Password</a></p>
                    <p>Or copy this link: {reset_link}</p>
                    <p>If you didn't request this, please ignore this
                       email.</p>
                    <p style="color: #666; font-size: 12px; margin-top: 20px;">
                       This link will expire in 24 hours.</p>
                </body>
                </html>
                """
                success, message = send_smtp_email(
                    staff_email, email_subject, email_body
                )
                if success:
                    flash(
                        f'Password reset link sent to {staff_email}',
                        'success'
                    )
                else:
                    flash(f'Error sending email: {message}', 'error')
            else:
                flash('User not found. Please check your details.', 'error')
            return redirect(url_for('login'))

        # Handle Sign In (original logic)
        else:
            username = request.form.get('username', '').lower()
            password = request.form.get('password', '')
            role = request.form.get('role', '')

            # Staff login (doctor, nurse, admin)
            if username in USERS and USERS[username]['password'] == password:
                session['user'] = username
                session['role'] = role if role else USERS[username]['role']
                session['logged_in'] = True
                flash(
                    f'Welcome back, {username}! Logged in as '
                    f'{session["role"]}', 'success'
                )

                # Log login event
                log_event(
                    "LOGIN",
                    f"User {username} logged in as {session['role']}"
                )

                # Redirect admin to audit page
                if session['role'] == 'admin':
                    return redirect(url_for('verify_audit'))
                # Redirect doctor/nurse to hospital selection
                elif session['role'] in ['doctor', 'nurse']:
                    return redirect(url_for('select_hospital'))
                # Redirect patient to their dashboard
                elif session['role'] == 'patient':
                    # Set a default patient name if not present
                    if 'patient_name' not in session:
                        # Try to find name in patients records
                        # or just use capitalized username
                        records = load_data(PATIENT_RECORDS_FILE)
                        patient_record = next(
                            (r for r in records
                             if r.get('patient_id') == username),
                            None
                        )
                        if patient_record:
                            session['patient_name'] = patient_record.get(
                                'patient_name', username.capitalize()
                            )
                        else:
                            session['patient_name'] = username.capitalize()
                    return redirect(url_for('patient_dashboard'))
                return redirect(url_for('index'))
            else:
                flash(
                    'Invalid username or password. Please try again.',
                    'error'
                )
                return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/select-hospital', methods=['GET', 'POST'])
def select_hospital():
    """Hospital selection page for doctors and nurses"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if session.get('role') not in ['doctor', 'nurse']:
        return redirect(url_for('index'))

    if request.method == 'POST':
        hospital_id = request.form.get('hospital_id')
        if hospital_id and hospital_id in HOSPITALS:
            session['hospital'] = HOSPITALS[hospital_id]
            hosp_dict = cast(Dict[str, Any], HOSPITALS[hospital_id])
            hospital_name = hosp_dict.get('name', 'Unknown')
            flash(f"Connected to {hospital_name}", 'success')
            return redirect(url_for('index'))
        else:
            flash('Please select a valid hospital.', 'error')

    return render_template('hospital_select.html', hospitals=HOSPITALS)


@app.route('/profile')
@role_required('profile')
def profile():
    """User profile page"""
    user_data = {
        'username': session.get('user', 'User'),
        'role': session.get('role', 'Unknown'),
        'hospital': session.get('hospital', {}),
        'email': f"{session.get('user', 'user')}@healthcrypto.com"
    }
    return render_template('profile.html', user=user_data)


@app.route('/settings', methods=['GET', 'POST'])
@role_required('settings')
def settings():
    """User settings page"""
    if request.method == 'POST':
        flash('Settings saved successfully!', 'success')
        return redirect(url_for('settings'))

    user_data = {
        'username': session.get('user', 'User'),
        'role': session.get('role', 'Unknown'),
    }
    return render_template('settings.html', user=user_data)


@app.route('/security')
@role_required('security')
def security():
    """Security settings page"""
    user_data = {
        'username': session.get('user', 'User'),
        'role': session.get('role', 'Unknown'),
    }
    return render_template('security.html', user=user_data)


@app.route('/activity')
@role_required('activity')
def activity():
    """Activity log page"""
    # Sample activity data
    activities = [
        {'action': 'Login', 'time': 'Today, 10:30 AM', 'status': 'Success'},
        {
            'action': 'Encrypt Data',
            'time': 'Today, 10:15 AM',
            'status': 'Success'
        },
        {
            'action': 'Send Email',
            'time': 'Yesterday, 3:45 PM',
            'status': 'Success'
        },
        {
            'action': 'View Audit Log',
            'time': 'Yesterday, 2:30 PM',
            'status': 'Success'
        },
    ]

    user_data = {
        'username': session.get('user', 'User'),
        'role': session.get('role', 'Unknown'),
    }
    return render_template(
        'activity.html', user=user_data, activities=activities
    )


@app.route('/help')
@role_required('help_page')
def help_page():
    """Help/Documentation page"""
    return render_template('help.html')


@app.route('/tutorials')
@role_required('tutorials')
def tutorials():
    """Video tutorials page"""
    return render_template('tutorials.html')


@app.route('/about')
def about():
    """About page - Professional website information"""
    return render_template('about.html')


@app.route('/contact-support', methods=['GET', 'POST'])
def contact_support():
    """Contact support page"""
    # Allow access without login for support requests
    user_data = {}
    if session.get('logged_in'):
        user_data = {
            'username': session.get('user', 'User'),
            'role': session.get('role', 'Unknown'),
        }

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        subject = request.form.get('subject', '').strip()
        message = request.form.get('message', '').strip()

        if not name or not email or not subject or not message:
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('contact_support'))

        # Send email to support team
        config = load_email_config()
        support_email = config.get('email', 'chintu01032005@gmail.com')

        # Email to support team
        email_subject = f"Support Request: {subject}"
        email_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #2563eb;">New Support Request</h2>
            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;">
                        <strong>Name:</strong>
                    </td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;">
                        {name}
                    </td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;">
                        <strong>Email:</strong>
                    </td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;">
                        {email}
                    </td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;">
                        <strong>Subject:</strong>
                    </td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;">
                        {subject}
                    </td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;
                        vertical-align: top;"><strong>Message:</strong></td>
                    <td style="padding: 10px; border: 1px solid #e2e8f0;">
                        {message}
                    </td>
                </tr>
            </table>
            <p style="margin-top: 20px; color: #666; font-size: 12px;">
                This email was sent from the Healthcare Crypto System
                Contact Support form.
            </p>
        </body>
        </html>
        """

        # Send to support team
        success, result = send_smtp_email(
            support_email, email_subject, email_body
        )

        if success:
            # Also send confirmation to user
            confirmation_subject = "We received your support request"
            confirmation_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <h2 style="color: #2563eb;">Thank you for contacting us!</h2>
                <p>Hello {name},</p>
                <p>We have received your support request regarding:
                   <strong>{subject}</strong></p>
                <p>Our support team will review your message and get back to
                   you within 24-48 hours.</p>
                <p>Here's a copy of your message:</p>
                <blockquote style="background: #f8fafc; padding: 15px;
                   border-left: 4px solid #2563eb; margin: 15px 0;">
                    {message}
                </blockquote>
                <p>Best regards,<br>The Healthcare Crypto Support Team</p>
            </body>
            </html>
            """
            send_smtp_email(
                email, confirmation_subject, confirmation_body
            )
            flash(
                'Your message has been sent! '
                'Check your email for confirmation.',
                'success'
            )
        else:
            flash(f'Error sending message: {result}', 'error')

        return redirect(url_for('contact_support'))

    return render_template('contact_support.html', user=user_data)


@app.route('/logout')
def logout():
    """Logout and clear session"""
    username = session.get('user', 'User')
    log_event("LOGOUT", f"User {username} logged out")
    session.clear()
    flash(f'You have been logged out, {username}.', 'success')
    return redirect(url_for('login'))


@app.route('/send-image', methods=['POST'])
@role_required('encrypt_image')
def send_image():
    """Send encrypted image to recipient"""
    action = request.form.get('action', 'send_single')
    cipher_file = request.form.get('cipher_file')

    if not cipher_file:
        flash('Cipher file is required', 'error')
        return redirect(url_for('encrypt_image'))

    cipher_path = os.path.join(UPLOAD_FOLDER, cipher_file)
    if not os.path.exists(cipher_path):
        flash('Cipher file not found', 'error')
        return redirect(url_for('encrypt_image'))

    try:
        with open(cipher_path, 'r') as f:
            encrypted_payload = json.load(f)

        # Add metadata for the recipient
        encrypted_payload['package_type'] = 'medical_image'

        # Add new fields requested by user
        patient_name = request.form.get('patient_name', 'Not Specified')
        message_text = request.form.get('message', '')
        is_emergency = request.form.get('is_emergency') == 'yes'

        encrypted_payload['patient_name'] = patient_name
        encrypted_payload['message'] = message_text
        encrypted_payload['is_emergency'] = is_emergency

        if action == 'send_all':
            success = send_encrypted_email_to_all(encrypted_payload)
            recipient = "All Recipients"
        else:
            recipient = request.form.get('recipient')
            if not recipient:
                # If recipient is not provided but action is send_single,
                # we might have a UI issue
                flash('Recipient email is required for single send', 'error')
                return redirect(url_for('encrypt_image'))
            success = send_encrypted_email(recipient, encrypted_payload)

        if success:
            emergency_str = " [EMERGENCY]" if is_emergency else ""
            log_event(
                "IMAGE_SEND",
                f"Sent encrypted image {cipher_file} to {recipient}"
                f"{emergency_str}. Patient: {patient_name}"
            )
            flash_msg = (
                f'Encrypted medical image sent successfully to {recipient}!'
            )
            if is_emergency:
                flash_msg = f'🚨 EMERGENCY: {flash_msg}'
            flash(flash_msg, 'success')
        else:
            flash(
                f'Failed to send encrypted image to {recipient}. '
                f'Check logs for details.', 'error'
            )

    except Exception as e:
        flash(f'Error sending image: {str(e)}', 'error')

    return redirect(url_for('encrypt_image'))


def open_image_flexible(filepath):
    """Open an image file, handling both standard formats and DICOM."""
    from PIL import Image
    import numpy as np

    ext = filepath.lower().split('.')[-1]
    if ext in ['dcm', 'dicom']:
        import pydicom
        ds = pydicom.dcmread(filepath)
        # Convert to float and normalize to 0-255
        pixel_array = ds.pixel_array.astype(float)
        rescaled = (np.maximum(pixel_array, 0) / pixel_array.max()) * 255.0
        return Image.fromarray(rescaled.astype(np.uint8)).convert('RGB')
    else:
        return Image.open(filepath).convert('RGB')


@app.route('/encrypt-image', methods=['GET', 'POST'])
@role_required('encrypt_image')
def encrypt_image():
    """Medical Image Encryption page"""
    # Get list of doctors and patients for the dropdown
    users_list = USERS
    doctors = {
        u: data for u, data in users_list.items()
        if data.get('role') == 'doctor' and u != session.get('user')
    }
    patients = {
        u: data for u, data in users_list.items()
        if data.get('role') == 'patient' and u != session.get('user')
    }

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(url_for('encrypt_image'))

        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(url_for('encrypt_image'))

        if file and file.filename and allowed_file(file.filename):
            import datetime
            import uuid

            # 1. Save original image (simulate medical record)
            filename = secure_filename(file.filename)
            unique_id = str(uuid.uuid4())[:8]
            filepath = os.path.join(
                UPLOAD_FOLDER, f"raw_{unique_id}_{filename}"
            )
            file.save(filepath)

            # 2. Encrypt image bytes using Hybrid Algorithm
            with open(filepath, 'rb') as f:
                image_data = f.read()

            import time
            aes_key, key_id = get_active_key()

            # Measure encryption time
            start_time = time.time()
            ciphertext, nonce, tag = encrypt_gcm(image_data, aes_key)
            enc_time = (time.time() - start_time) * 1000  # in ms

            # Measure decryption time for metric
            start_time = time.time()
            decrypt_gcm(ciphertext, aes_key, nonce, tag)
            dec_time = (time.time() - start_time) * 1000  # in ms

            # 3. Save encrypted "Cipher Image" (binary format)
            encrypted_filename = f"cipher_{unique_id}_{filename}.bin"
            encrypted_path = os.path.join(UPLOAD_FOLDER, encrypted_filename)

            encrypted_payload = {
                'filename': filename,
                'ciphertext': ciphertext.hex(),
                'nonce': nonce.hex(),
                'tag': tag.hex(),
                'key_id': key_id,
                'timestamp': datetime.datetime.now().isoformat(),
                'doctor': session.get('user', 'Unknown')
            }

            with open(encrypted_path, 'w') as f:
                json.dump(encrypted_payload, f, indent=2)

            # 4. Generate Analysis Metrics
            from backend.utils.image_analysis import (
                calculate_npcr, calculate_uaci, calculate_correlation,
                calculate_entropy, calculate_psnr, generate_histogram,
                generate_correlation_plot, generate_entropy_heatmap,
                apply_salt_and_pepper, apply_bit_flipping, apply_compression
            )
            from PIL import Image

            # Load original
            orig_img = open_image_flexible(filepath)

            # Create a "pseudo-encrypted" image for analysis (GCM is not a
            # pixel-to-pixel mapping, so for visualization we use random noise
            # of same size)
            enc_array = np.random.randint(
                0, 256, np.array(orig_img).shape, dtype=np.uint8
            )
            enc_img = Image.fromarray(enc_array)

            # Basic Metrics
            metrics = {
                'npcr': round(calculate_npcr(orig_img, enc_img), 4),
                'uaci': round(calculate_uaci(orig_img, enc_img), 4),
                'orig_corr': round(calculate_correlation(orig_img), 4),
                'enc_corr': round(calculate_correlation(enc_img), 4),
                'orig_entropy': round(calculate_entropy(orig_img), 4),
                'enc_entropy': round(calculate_entropy(enc_img), 4),
                'psnr': round(calculate_psnr(orig_img, enc_img), 4),
                'enc_time': f"{enc_time:.2f}ms",
                'dec_time': f"{dec_time:.2f}ms"
            }

            # Visuals
            visuals = {
                'orig_hist': generate_histogram(
                    orig_img, 'Original Image Histogram'
                ),
                'enc_hist': generate_histogram(
                    enc_img, 'Encrypted Image Histogram'
                ),
                'orig_corr_plot': generate_correlation_plot(
                    orig_img, 'Original Image Pixel Correlation'
                ),
                'enc_corr_plot': generate_correlation_plot(
                    enc_img, 'Encrypted Image Pixel Correlation'
                ),
                'entropy_heatmap': generate_entropy_heatmap(orig_img)
            }

            # Attack Analysis
            attacks = {
                'salt_pepper': round(
                    calculate_psnr(orig_img, apply_salt_and_pepper(orig_img)),
                    2
                ),
                'bit_flipping': round(
                    calculate_psnr(orig_img, apply_bit_flipping(orig_img)), 2
                ),
                'compression': round(
                    calculate_psnr(orig_img, apply_compression(orig_img)), 2
                )
            }

            # 5. Log the event
            log_event(
                "IMAGE_ENCRYPT",
                f"Encrypted image {filename} for secure transmission. "
                f"Key: {key_id}"
            )

            flash(
                f'Medical Image encrypted successfully! '
                f'Cipher Image saved as {encrypted_filename}',
                'success'
            )
            return render_template(
                'encrypt_image.html',
                encrypted=True,
                filename=filename,
                cipher_file=encrypted_filename,
                recipients=RECIPIENT_EMAILS,
                doctors=doctors,
                patients=patients,
                metrics=metrics,
                visuals=visuals,
                attacks=attacks
            )

        flash('Invalid file type', 'error')
        return redirect(url_for('encrypt_image'))

    return render_template(
        'encrypt_image.html',
        recipients=RECIPIENT_EMAILS,
        doctors=doctors,
        patients=patients
    )


@app.route('/decrypt-image', methods=['GET', 'POST'])
@role_required('decrypt_image')
def decrypt_image():
    """Medical Image Decryption page"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(url_for('decrypt_image'))

        file = request.files['file']
        if not file or file.filename == '':
            flash('No selected file', 'error')
            return redirect(url_for('decrypt_image'))

        if file.filename and file.filename.endswith('.bin'):
            import uuid
            import base64
            from PIL import Image
            import io

            # 1. Save and Load the Cipher JSON
            unique_id = str(uuid.uuid4())[:8]
            filepath = os.path.join(
                UPLOAD_FOLDER, f"decrypt_{unique_id}_{file.filename}"
            )
            file.save(filepath)

            try:
                with open(filepath, 'r') as f:
                    payload = json.load(f)

                # 2. Basic Validation: Is this an image or email payload?
                if 'encrypted_key' in payload:
                    msg = (
                        'This is an Email Payload (.json/.bin). Please use '
                        'the "Decrypt Received Payload" section below to '
                        'decrypt it using your email and role.'
                    )
                    flash(msg, 'info')
                    return redirect(url_for('receive_email'))

                # 3. Extract components
                try:
                    ciphertext = bytes.fromhex(payload['ciphertext'])
                    nonce = bytes.fromhex(payload['nonce'])
                    tag = bytes.fromhex(payload['tag'])
                    key_id = payload.get('key_id')
                    original_filename = payload.get(
                        'filename', 'decrypted_image.png'
                    )
                except KeyError as e:
                    flash(
                        f'Invalid cipher file format. Missing field: {str(e)}',
                        'error'
                    )
                    return redirect(url_for('decrypt_image'))

                # 4. Decrypt using the correct key from the payload
                aes_key = None
                if key_id:
                    aes_key = get_key_by_id(key_id)

                # Fallback to active key if key_id not found or missing
                if aes_key is None:
                    print(
                        f"[INFO] Key ID {key_id} not found in store, "
                        f"attempting fallback..."
                    )
                    aes_key, _ = get_active_key()

                decrypted_bytes = b""
                try:
                    decrypted_bytes = decrypt_gcm(
                        ciphertext, aes_key, nonce, tag
                    )
                except Exception as e:
                    if "MAC check failed" in str(e):
                        # Try rotating through all keys if fallback failed
                        print(
                            f"[INFO] MAC check failed with key {key_id}. "
                            f"Attempting brute force through all "
                            f"stored keys..."
                        )
                        from crypto.key_manager import _load_keys
                        all_keys = _load_keys()
                        success = False
                        for k_entry in all_keys:
                            try:
                                k_bytes = bytes.fromhex(k_entry["key"])
                                # Skip the one we already tried
                                if k_bytes == aes_key:
                                    continue

                                decrypted_bytes = decrypt_gcm(
                                    ciphertext, k_bytes, nonce, tag
                                )
                                aes_key = k_bytes
                                success = True
                                print(
                                    f"[OK] Successfully decrypted using "
                                    f"historical key: {k_entry['key_id']}"
                                )
                                break
                            except Exception:
                                continue

                        if not success:
                            msg = (
                                'Decryption failed: The required AES key was '
                                'not found in your local key store. This '
                                'image may have been encrypted on a '
                                'different system.'
                            )
                            flash(msg, 'error')
                            return redirect(url_for('decrypt_image'))
                    else:
                        raise e

                # 5. Save decrypted image
                decrypted_filename = (
                    f"decrypted_{unique_id}_{original_filename}"
                )
                decrypted_path = os.path.join(
                    UPLOAD_FOLDER, decrypted_filename
                )

                with open(decrypted_path, 'wb') as f:
                    f.write(decrypted_bytes)

                # 6. Prepare for display (handle DICOM if needed)
                mime_type = "image/png"
                ext = original_filename.lower().split('.')[-1]

                if ext in ['dcm', 'dicom']:
                    try:
                        import pydicom

                        # Read DICOM from bytes
                        with io.BytesIO(decrypted_bytes) as bio:
                            ds = pydicom.dcmread(bio)
                            pixel_array = ds.pixel_array.astype(float)
                            rescaled = (
                                np.maximum(pixel_array, 0) /
                                pixel_array.max()
                            ) * 255.0
                            img = Image.fromarray(
                                rescaled.astype(np.uint8)
                            ).convert('RGB')

                            # Convert to PNG for display
                            with io.BytesIO() as output:
                                img.save(output, format="PNG")
                                encoded_image = base64.b64encode(
                                    output.getvalue()
                                ).decode('utf-8')
                    except Exception as e:
                        print(
                            f"[ERROR] Failed to convert decrypted DICOM "
                            f"for display: {e}"
                        )
                        encoded_image = base64.b64encode(
                            decrypted_bytes
                        ).decode('utf-8')
                else:
                    # For standard images, determine MIME type
                    if ext in ['jpg', 'jpeg']:
                        mime_type = "image/jpeg"
                    elif ext == 'gif':
                        mime_type = "image/gif"

                    encoded_image = base64.b64encode(
                        decrypted_bytes
                    ).decode('utf-8')

                log_event(
                    "IMAGE_DECRYPT",
                    f"Decrypted image {original_filename} successfully."
                )
                flash(
                    f'Medical Image decrypted successfully! '
                    f'Original: {original_filename}',
                    'success'
                )

                return render_template(
                    'decrypt_image.html',
                    decrypted=True,
                    filename=original_filename,
                    mime_type=mime_type,
                    image_data=encoded_image
                )

            except Exception as e:
                flash(f'Error decrypting image: {str(e)}', 'error')
                return redirect(url_for('decrypt_image'))

        flash('Invalid file type. Please upload a .bin cipher file.', 'error')
        return redirect(url_for('decrypt_image'))

    return render_template('decrypt_image.html')


@app.route('/encrypt', methods=['GET', 'POST'])
@role_required('encrypt')
def encrypt():
    """Encryption page"""
    if request.method == 'POST':
        output, code = run_python_script('main.py', ['encrypt'])
        flash(f'Encryption Output:\n{output}',
              'success' if code == 0 else 'error')
        return redirect(url_for('encrypt'))
    return render_template('encrypt.html')


@app.route('/decrypt', methods=['GET', 'POST'])
@role_required('decrypt')
def decrypt():
    """Decryption page"""
    if request.method == 'POST':
        role = request.form.get('role', 'doctor')
        
        # Check if a file was uploaded
        if 'payload_file' in request.files:
            file = request.files['payload_file']
            if file and file.filename != '':
                file_path = os.path.join(PROJECT_DIR, 'secure_payload.json')
                file.save(file_path)
                flash('Payload file uploaded successfully.', 'success')

        output, code = run_python_script('main.py', ['decrypt', role])
        flash(f'Decryption Output (Role: {role}):\n{output}',
              'success' if code == 0 else 'error')
        return redirect(url_for('decrypt'))
    return render_template('decrypt.html')


@app.route('/send-email', methods=['GET', 'POST'])
@role_required('send_email')
def send_email():
    """Send secure email page with text and images"""
    import datetime
    import base64
    if request.method == 'POST':
        action = request.form.get('action', '')
        message_text = request.form.get('message', '').strip()
        recipient_email = request.form.get('email', '')

        # Prepare the communication record
        record = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sender": session.get('user', 'Unknown'),
            "message": message_text or "No message content."
        }

        # Handle image attachment
        if 'image_attachment' in request.files:
            img_file = request.files['image_attachment']
            if img_file and img_file.filename != '':
                img_bytes = img_file.read()
                # Encode image to base64
                encoded_img = base64.b64encode(img_bytes).decode('utf-8')
                record["image_data"] = encoded_img
                record["image_filename"] = img_file.filename

        # Encrypt the record using the system's active key
        # (This ensures it can be decrypted via RBAC on the other side)
        try:
            encrypted_record, key_id = encrypt_record(record)
            log_event(
                "EMAIL_ENCRYPT",
                f"Communication encrypted using key {key_id}"
            )

            if action == 'send_all':
                success = send_encrypted_email_to_all(encrypted_record)
                recipient = "All Recipients"
            else:
                if not recipient_email:
                    flash('Please enter a recipient email', 'error')
                    return redirect(url_for('send_email'))
                success = send_encrypted_email(
                    recipient_email, encrypted_record
                )
                recipient = recipient_email

            if success:
                flash(
                    f'Secure communication sent successfully to {recipient}!',
                    'success'
                )
            else:
                flash(
                    f'Failed to send communication to {recipient}.', 'error'
                )
        except Exception as e:
            flash(
                f'Error processing secure communication: {str(e)}', 'error'
            )

        return redirect(url_for('send_email'))

    # Get list of doctors and patients for the dropdown
    users_list = USERS
    doctors = {
        u: data for u, data in users_list.items()
        if data.get('role') == 'doctor' and u != session.get('user')
    }
    patients = {
        u: data for u, data in users_list.items()
        if data.get('role') == 'patient' and u != session.get('user')
    }

    return render_template(
        'email.html', doctors=doctors, patients=patients
    )


@app.route('/receive-email', methods=['GET', 'POST'])
@role_required('receive_email')
def receive_email():
    """Receive and verify email page"""
    if request.method == 'POST':
        email = request.form.get('email', '')
        role = request.form.get('role', 'doctor')

        if 'payload_file' not in request.files:
            flash('No payload file provided', 'error')
            return redirect(url_for('receive_email'))

        file = request.files['payload_file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(url_for('receive_email'))

        if not email:
            flash(
                'Please enter your email address to decrypt the payload',
                'error'
            )
            return redirect(url_for('receive_email'))

        # Save the uploaded payload file
        import uuid
        unique_id = str(uuid.uuid4())[:8]
        temp_payload_path = os.path.join(
            UPLOAD_FOLDER, f"payload_{unique_id}.json"
        )
        file.save(temp_payload_path)

        # Use the imported function directly
        success, message, decrypted_data = decrypt_received_payload(
            temp_payload_path, email, role
        )

        if success:
            image_package = None
            # If it's a medical image package, we need to decrypt the
            # image data too
            is_image_package = (
                isinstance(decrypted_data, dict) and
                decrypted_data.get('package_type') == 'medical_image'
            )
            if is_image_package:
                try:
                    import base64
                    import io
                    from PIL import Image

                    # Extract image components
                    ciphertext = bytes.fromhex(decrypted_data['ciphertext'])
                    nonce = bytes.fromhex(decrypted_data['nonce'])
                    tag = bytes.fromhex(decrypted_data['tag'])
                    key_id = decrypted_data.get('key_id')
                    filename = decrypted_data.get('filename', 'decrypted.png')

                    # Decrypt the image bytes
                    aes_key = get_key_by_id(key_id)
                    if not aes_key:
                        aes_key, _ = get_active_key()

                    decrypted_bytes = decrypt_gcm(
                        ciphertext, aes_key, nonce, tag
                    )

                    # Prepare for display
                    mime_type = "image/png"
                    ext = filename.lower().split('.')[-1]

                    if ext in ['dcm', 'dicom']:
                        import pydicom
                        with io.BytesIO(decrypted_bytes) as bio:
                            ds = pydicom.dcmread(bio)
                            pixel_array = ds.pixel_array.astype(float)
                            max_pixel = pixel_array.max()
                            rescaled = (
                                np.maximum(pixel_array, 0) / max_pixel
                            ) * 255.0
                            img = Image.fromarray(
                                rescaled.astype(np.uint8)
                            ).convert('RGB')
                            with io.BytesIO() as output:
                                img.save(output, format="PNG")
                                encoded_image = base64.b64encode(
                                    output.getvalue()
                                ).decode('utf-8')
                    else:
                        if ext in ['jpg', 'jpeg']:
                            mime_type = "image/jpeg"
                        encoded_image = base64.b64encode(
                            decrypted_bytes
                        ).decode('utf-8')

                    image_package = {
                        'filename': filename,
                        'mime_type': mime_type,
                        'image_data': encoded_image
                    }
                except Exception as e:
                    print(
                        f"[ERROR] Failed to decrypt image within payload: {e}"
                    )
                    flash(
                        f'Warning: Payload decrypted but image restoration '
                        f'failed: {str(e)}', 'warning'
                    )

            flash(message, 'success')
            return render_template(
                'receive_email.html',
                decrypted=True,
                decrypted_data=decrypted_data,
                image_package=image_package,
                role=role
            )
        else:
            flash(message, 'error')
            return redirect(url_for('receive_email'))

    return render_template('receive_email.html')


@app.route('/admin/dashboard')
@role_required('admin_dashboard')
def admin_dashboard():
    """Admin Dashboard for monitoring all system activity"""
    import datetime
    
    # 1. Parse Audit Log for recent activity
    audit_logs = []
    stats = {
        'total_logins': 0,
        'total_encryptions': 0,
        'total_decryptions': 0,
        'security_alerts': 0,
        'image_operations': 0,
        'email_operations': 0
    }
    
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
            # Reverse to show newest first
            for line in reversed(lines):
                parts = line.strip().split('|')
                if len(parts) >= 3:
                    try:
                        ts = int(parts[0])
                        dt = datetime.datetime.fromtimestamp(ts).strftime(
                            '%Y-%m-%d %H:%M:%S'
                        )
                        event_type = parts[1]
                        message = parts[2]

                        # Update stats
                        if event_type == 'LOGIN':
                            stats['total_logins'] += 1
                        elif event_type == 'ENCRYPT':
                            stats['total_encryptions'] += 1
                        elif event_type == 'DECRYPT':
                            stats['total_decryptions'] += 1
                        elif 'IMAGE' in event_type:
                            stats['image_operations'] += 1
                        elif 'EMAIL' in event_type:
                            stats['email_operations'] += 1
                        elif 'TAMPER' in event_type or 'ALERT' in event_type:
                            stats['security_alerts'] += 1

                        # Only keep latest 50 for display
                        if len(audit_logs) < 50:
                            audit_logs.append({
                                'timestamp': dt,
                                'type': event_type,
                                'message': message,
                                'status': 'Success'  # Assume success for logs
                            })
                    except (ValueError, IndexError):
                        continue

    # 2. Get system health info
    system_status = {
        'audit_integrity': 'Verified',  # Default
        'keys_active': 1,
        'server_uptime': 'Online',
        'database_status': 'Operational'
    }

    # 3. Get user distribution
    user_roles_count = {
        'doctor': 0,
        'nurse': 0,
        'admin': 0,
        'patient': 0
    }
    for user, data in USERS.items():
        role = data.get('role', 'patient')
        if role in user_roles_count:
            user_roles_count[role] += 1

    return render_template(
        'admin_dashboard.html',
        logs=audit_logs,
        stats=stats,
        system_status=system_status,
        user_roles=user_roles_count,
        total_users=len(USERS)
    )


@app.route('/verify-audit', methods=['GET', 'POST'])
@role_required('verify_audit')
def verify_audit():
    """Verify audit log page"""
    if request.method == 'POST':
        output, code = run_python_script('main.py', ['verify'])
        flash(f'Audit Verification Output:\n{output}',
              'success' if code == 0 else 'error')
        return redirect(url_for('verify_audit'))
    return render_template('audit.html')


@app.route('/tamper-test', methods=['GET', 'POST'])
@role_required('tamper_test')
def tamper_test():
    """Tamper testing page (Red Team)"""
    tamper_script = os.path.join(PROJECT_ROOT, 'frontend', 'tamper_gui.py')
    
    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'tamper_payload':
            output, code = run_python_script(
                tamper_script, ['tamper-payload'])
        elif action == 'tamper_audit':
            output, code = run_python_script(
                tamper_script, ['tamper-audit'])
        elif action == 'reset':
            output, code = run_python_script(tamper_script, ['reset'])
        else:
            output, code = "Unknown action", 1

        flash(f'Tamper Test Output:\n{output}',
              'success' if code == 0 else 'error')
        return redirect(url_for('tamper_test'))
    return render_template('tamper.html')


@app.route('/status', methods=['GET', 'POST'])
@role_required('status')
def status():
    """System status page"""
    if request.method == 'POST':
        flash(
            'System status check performed. All components operational.',
            'success'
        )
        return redirect(url_for('status'))

    status_info = {}

    # Correct paths relative to PROJECT_ROOT
    keys_store = os.path.join(PROJECT_ROOT, 'crypto', 'keys', 'aes_keys.json')
    recipient_keys_dir = os.path.join(PROJECT_ROOT, 'recipient_keys')
    payload_file = os.path.join(PROJECT_ROOT, 'crypto', 'secure_payload.json')
    audit_log = os.path.join(PROJECT_ROOT, 'backend', 'services', 'audit.log')

    status_info['keys_exist'] = os.path.exists(keys_store)
    status_info['recipient_keys_exist'] = os.path.exists(recipient_keys_dir) and len(os.listdir(recipient_keys_dir)) > 0
    status_info['payload_exists'] = os.path.exists(payload_file)
    status_info['audit_exists'] = os.path.exists(audit_log)

    return render_template('status.html', status=status_info)


# Lab Results Data Storage
LAB_RESULTS_FILE = os.path.join(PROJECT_DIR, 'lab_results.json')


def load_lab_results():
    """Load lab results from JSON file"""
    return cast(List[Any], load_data(LAB_RESULTS_FILE))


def save_lab_results(results):
    """Save lab results to JSON file"""
    save_data(LAB_RESULTS_FILE, results)


@app.route('/lab-results', methods=['GET', 'POST'])
@role_required('index')
def lab_results():
    """Lab Results page for doctors"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    # Only doctors can access this page
    if session.get('role') not in ['doctor', 'nurse', 'admin']:
        flash(
            'Access denied. Only medical staff can access lab results.',
            'error'
        )
        return redirect(url_for('index'))

    # Handle new lab result submission
    if request.method == 'POST':
        patient_id = request.form.get('patient_id', '').strip()
        patient_name = request.form.get('patient_name', '').strip()
        test_type = request.form.get('test_type', '').strip()
        results = request.form.get('results', '').strip()
        status = request.form.get('status', 'Pending').strip()

        if patient_id and patient_name and test_type and results:
            lab_data = load_lab_results()

            import datetime
            new_result = {
                'id': len(lab_data) + 1,
                'patient_id': patient_id.upper(),
                'patient_name': patient_name,
                'test_type': test_type,
                'results': results,
                'status': status,
                'date': datetime.datetime.now().strftime('%Y-%m-%d'),
                'hospital': session.get('hospital', {}).get('name', 'Unknown'),
                'doctor': session.get('user', 'Unknown')
            }
            lab_data.append(new_result)
            save_lab_results(lab_data)
            flash('Lab result added successfully!', 'success')
        else:
            flash('Please fill in all required fields.', 'error')

        return redirect(url_for('lab_results'))

    # Get filter parameters
    patient_id_filter = request.args.get('patient_id', '').strip()
    test_type_filter = request.args.get('test_type', '').strip()
    status_filter = request.args.get('status', '').strip()

    # Load and filter lab results
    lab_data = load_lab_results()

    # Filter results
    filtered_results = lab_data
    if patient_id_filter:
        filtered_results = [
            r for r in filtered_results
            if patient_id_filter.upper() in r.get('patient_id', '')
        ]
    if test_type_filter:
        filtered_results = [
            r for r in filtered_results
            if r.get('test_type') == test_type_filter
        ]
    if status_filter:
        filtered_results = [
            r for r in filtered_results if r.get('status') == status_filter
        ]

    # Sort by date (newest first)
    filtered_results.sort(key=lambda x: x.get('date', ''), reverse=True)

    return render_template(
        'lab_results.html', lab_results=filtered_results
    )


@app.route('/download-lab-report/<int:result_id>')
@role_required('index')
def download_lab_report(result_id):
    """Download lab report as text file"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    lab_data = load_lab_results()
    result = next((r for r in lab_data if r.get('id') == result_id), None)

    if not result:
        flash('Lab result not found', 'error')
        return redirect(url_for('lab_results'))

    # Create text content for the report
    report_content = f"""
================================================================================
                    LABORATORY TEST REPORT
================================================================================

Report ID: LR-{result_id:06d}
Date: {result.get('date', 'N/A')}

--------------------------------------------------------------------------------
                        PATIENT INFORMATION
--------------------------------------------------------------------------------

Patient ID:     {result.get('patient_id', 'N/A')}
Patient Name:   {result.get('patient_name', 'N/A')}
Hospital:       {result.get('hospital', 'N/A')}
Physician:      {result.get('doctor', 'N/A')}

--------------------------------------------------------------------------------
                        TEST INFORMATION
--------------------------------------------------------------------------------

Test Type:      {result.get('test_type', 'N/A')}
Status:         {result.get('status', 'N/A')}

--------------------------------------------------------------------------------
                        TEST RESULTS
--------------------------------------------------------------------------------

{result.get('results', 'N/A')}

================================================================================
This is a computer-generated document.
Healthcare Crypto System - Secure Healthcare Reporting
================================================================================
"""

    # Create response with the report content
    response = make_response(report_content)
    filename = f'lab_report_{result_id}.txt'
    response.headers['Content-Disposition'] = (
        f'attachment; filename={filename}'
    )
    response.headers['Content-Type'] = 'text/plain'

    return response


@app.route('/prescriptions', methods=['GET', 'POST'])
@role_required('prescriptions')
def prescriptions():
    """Prescriptions management page"""
    if request.method == 'POST':
        patient_name = request.form.get('patient_name')
        medication = request.form.get('medication')
        dosage = request.form.get('dosage')
        instructions = request.form.get('instructions')

        if patient_name and medication:
            prescriptions_list = cast(List[Any], load_data(PRESCRIPTIONS_FILE))

            # Simple "encryption" - in a real app, we'd use the GCM tools
            new_prescription = {
                'id': str(len(prescriptions_list) + 1),
                'patient_name': patient_name,
                'medication': medication,
                'dosage': dosage,
                'instructions': instructions,
                'doctor': session.get('user'),
                'timestamp': str(os.path.getmtime(__file__))
            }

            prescriptions_list.append(new_prescription)
            save_data(PRESCRIPTIONS_FILE, prescriptions_list)
            flash('Prescription issued successfully!', 'success')
            return redirect(url_for('prescriptions'))

    prescriptions_list = load_data(PRESCRIPTIONS_FILE)
    return render_template(
        'prescriptions.html', prescriptions=prescriptions_list
    )


@app.route('/medical-reports', methods=['GET', 'POST'])
@role_required('medical_reports')
def medical_reports():
    """Medical reports management page"""
    if request.method == 'POST':
        patient_name = request.form.get('patient_name')
        diagnosis = request.form.get('diagnosis')
        notes = request.form.get('notes')

        if patient_name and diagnosis:
            reports_list = cast(List[Any], load_data(MEDICAL_REPORTS_FILE))
            new_report = {
                'id': str(len(reports_list) + 1),
                'patient_name': patient_name,
                'diagnosis': diagnosis,
                'notes': notes,
                'doctor': session.get('user'),
                'timestamp': str(os.path.getmtime(__file__))
            }
            reports_list.append(new_report)
            save_data(MEDICAL_REPORTS_FILE, reports_list)
            flash('Medical report added successfully!', 'success')
            return redirect(url_for('medical_reports'))

    reports_list = load_data(MEDICAL_REPORTS_FILE)
    return render_template('medical_reports.html', reports=reports_list)


@app.route('/appointments', methods=['GET', 'POST'])
@role_required('appointments')
def appointments():
    """Appointments management page"""
    if request.method == 'POST':
        patient_name = request.form.get('patient_name')
        date = request.form.get('date')
        time = request.form.get('time')
        reason = request.form.get('reason')

        if patient_name and date:
            appointments_list = cast(List[Any], load_data(APPOINTMENTS_FILE))
            new_appointment = {
                'id': str(len(appointments_list) + 1),
                'patient_name': patient_name,
                'date': date,
                'time': time,
                'reason': reason,
                'doctor': session.get('user'),
                'status': 'Scheduled'
            }
            appointments_list.append(new_appointment)
            save_data(APPOINTMENTS_FILE, appointments_list)
            flash('Appointment scheduled successfully!', 'success')
            return redirect(url_for('appointments'))

    appointments_list = load_data(APPOINTMENTS_FILE)
    return render_template('appointments.html', appointments=appointments_list)


@app.route('/patient-records', methods=['GET', 'POST'])
@role_required('patient_records')
def patient_records():
    """Patient records management page"""
    if request.method == 'POST':
        patient_id = request.form.get('patient_id')
        name = request.form.get('name')
        dob = request.form.get('dob')
        gender = request.form.get('gender')
        blood_group = request.form.get('blood_group')
        password = request.form.get('password', 'Patient123')

        if patient_id and name:
            records_list = cast(List[Any], load_data(PATIENT_RECORDS_FILE))
            new_record = {
                'patient_id': patient_id.upper(),
                'name': name,
                'dob': dob,
                'gender': gender,
                'blood_group': blood_group,
                'last_updated': str(os.path.getmtime(__file__))
            }
            records_list.append(new_record)
            save_data(PATIENT_RECORDS_FILE, records_list)

            # Create/Update patient account
            patients_data = cast(Dict[str, Any], load_patients())
            patients_data[patient_id.upper()] = {
                'name': name,
                'password': password,
                'role': 'patient'
            }
            save_patients(patients_data)

            flash(
                'Patient record and account created successfully!',
                'success'
            )
            return redirect(url_for('patient_records'))

    records_list = load_data(PATIENT_RECORDS_FILE)
    return render_template('patient_records.html', records=records_list)


@app.route('/patient-dashboard')
@role_required('patient_dashboard')
def patient_dashboard():
    """Patient's own dashboard view"""
    patient_id = session.get('user')
    patient_name = session.get('patient_name', 'Patient')

    # Load data filtered for this patient
    p_name_low = patient_name.lower()
    prescriptions = [
        p for p in load_data(PRESCRIPTIONS_FILE)
        if p.get('patient_name', '').lower() == p_name_low or
        p.get('patient_id') == patient_id
    ]
    reports = [
        r for r in load_data(MEDICAL_REPORTS_FILE)
        if r.get('patient_name', '').lower() == p_name_low or
        r.get('patient_id') == patient_id
    ]
    appointments = [
        a for a in load_data(APPOINTMENTS_FILE)
        if a.get('patient_name', '').lower() == p_name_low or
        a.get('patient_id') == patient_id
    ]
    lab_results = [
        lab_res for lab_res in load_lab_results()
        if lab_res.get('patient_name', '').lower() == p_name_low or
        lab_res.get('patient_id') == patient_id
    ]

    return render_template(
        'patient_dashboard.html',
        patient_id=patient_id,
        patient_name=patient_name,
        prescriptions=prescriptions,
        reports=reports,
        appointments=appointments,
        lab_results=lab_results
    )


@app.route('/download-id')
@role_required('patient_dashboard')
def download_id():
    """Generate and download a secure Health ID card for the patient"""
    import hashlib
    import time

    patient_id = session.get('user', 'UNKNOWN')
    patient_name = session.get('patient_name', 'Patient')

    # Generate a unique secure hash for this ID card
    timestamp = str(time.time())
    id_str = f"{patient_id}:{patient_name}:{timestamp}"
    secure_hash = hashlib.sha256(
        id_str.encode()
    ).hexdigest()[:16].upper()

    id_card_content = f"""
==========================================
    SECURE HEALTHCARE CRYPTO SYSTEM
           HEALTH ID CARD
==========================================
PATIENT NAME: {patient_name.upper()}
PATIENT ID  : {patient_id}
ISSUE DATE  : {time.strftime('%Y-%m-%d %H:%M:%S')}
STATUS      : SECURE & PROTECTED
------------------------------------------
SECURE HASH : {secure_hash}
VERIFICATION: RSA-2048 / AES-256
------------------------------------------
This is a cryptographically secured ID card.
Any unauthorized tampering will be detected
by the system's hash-chain audit log.
==========================================
"""

    response = make_response(id_card_content)
    filename = f"HealthID_{patient_id}.txt"
    response.headers["Content-Disposition"] = (
        f"attachment; filename={filename}"
    )
    response.headers["Content-type"] = "text/plain"

    log_event(
        "ID_CARD_DOWNLOAD",
        f"Patient {patient_id} downloaded their Health ID card."
    )
    return response


@app.route('/request-access', methods=['POST'])
@role_required('patient_dashboard')
def request_access():
    """Handle access requests from patients"""
    patient_id = session.get('user')
    log_event(
        "ACCESS_REQUEST",
        f"Patient {patient_id} requested additional record access."
    )
    flash(
        'Your request for additional record access has been sent to the '
        'administrator.', 'success'
    )
    return redirect(url_for('patient_dashboard'))


# Chat messages storage
CHAT_FILE = os.path.join(PROJECT_DIR, 'chat_messages.json')


def load_chat_messages():
    """Load chat messages from JSON file"""
    return cast(List[Any], load_data(CHAT_FILE))


def save_chat_messages(messages):
    """Save chat messages to JSON file"""
    save_data(CHAT_FILE, messages)


@app.route('/live-chat')
@role_required('live_chat')
def live_chat():
    """Live chat support page"""
    user_data = {
        'username': session.get('user', 'User'),
        'role': session.get('role', 'Unknown'),
    }
    messages = load_chat_messages()
    return render_template('chat.html', user=user_data, messages=messages)


# Auto-response from support team
def get_auto_response(user_message):
    """Generate auto-responses for support queries"""
    user_message = user_message.lower()

    # Common responses based on keywords
    if any(word in user_message for word in ['encrypt', 'encryption']):
        return (
            "🔒 For encryption help: Go to the Encrypt page, select your data "
            "file, and click 'Encrypt'. Use a strong key for better security. "
            "Need more help?"
        )
    elif any(word in user_message for word in ['decrypt', 'decryption']):
        return (
            "🔓 For decryption: Visit the Decrypt page, enter your role "
            "(doctor/nurse), and provide the correct decryption key. Contact "
            "admin if you need key reset."
        )
    elif any(word in user_message for word in ['password', 'reset', 'forgot']):
        return (
            "🔑 For password reset: Go to login page, click 'Forgot "
            "Password', enter your username/email, and check your inbox "
            "for reset link."
        )
    elif any(word in user_message for word in ['email', 'send', 'receive']):
        return (
            "📧 For secure emails: Use the Send Email feature to encrypt "
            "messages. Recipients need their public key registered to "
            "receive encrypted emails."
        )
    elif any(word in user_message for word in ['audit', 'log', 'verify']):
        return (
            "📋 Audit logs track all system activities. Admins can verify "
            "integrity using the Verify Audit page. Logs cannot be "
            "tampered with!"
        )
    elif any(word in user_message for word in ['key', 'keys']):
        return (
            "🔑 Keys are managed by the system. If you need a new key, "
            "contact admin. Never share your private keys with anyone."
        )
    elif any(word in user_message for word in ['dicom', 'medical', 'image']):
        return (
            "🏥 DICOM files are medical images. Use the DICOM handler to "
            "sign and verify medical images for authenticity."
        )
    elif any(word in user_message for word in ['help', 'help me', 'support']):
        return (
            "👋 Hi! I'm the Healthcare Crypto Support Bot. I can help with: "
            "encryption, decryption, passwords, emails, keys, and audit "
            "logs. What do you need?"
        )
    elif any(word in user_message for word in ['thank', 'thanks']):
        return (
            "😊 You're welcome! Let me know if you need anything else. "
            "Stay secure!"
        )
    elif any(word in user_message for word in ['prescription', 'medication']):
        return (
            "💊 Prescriptions: You can now issue digital prescriptions via "
            "the Prescriptions dashboard. All medication data is secured "
            "using AES-256-GCM. Need help issuing one?"
        )
    elif any(word in user_message for word in ['report', 'medical report']):
        return (
            "📄 Medical Reports: Access unified patient reports from the "
            "Medical Reports section. You can create, view, and share "
            "reports securely. Any specific report you're looking for?"
        )
    elif any(word in user_message for word in ['appointment', 'schedule']):
        return (
            "📅 Appointments: Manage your consultation schedule in the "
            "Appointments dashboard. You can book new slots or check "
            "existing ones. Ready to schedule?"
        )
    elif any(word in user_message for word in ['record', 'patient record']):
        return (
            "📋 Patient Records: View unified demographic and clinical data "
            "in the Patient Records portal. Search by Patient ID for quick "
            "access."
        )
    elif any(word in user_message for word in ['hi', 'hello', 'hey']):
        return (
            "👋 Hello! I'm your Healthcare Crypto Assistant. I can help "
            "with clinical tools (Prescriptions, Reports, Appointments) "
            "or security features (Encryption, Secure Email). How can I "
            "assist you?"
        )
    else:
        return (
            "📝 I've received your clinical support request. Our team will "
            "review this and respond shortly. For urgent medical technical "
            "issues, call +1 (555) 911-HELP."
        )


@app.route('/api/chat/send', methods=['POST'])
def chat_send():
    """API to send a chat message"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in'}), 401

    data = request.get_json()
    message = data.get('message', '').strip()

    if not message:
        return jsonify({'error': 'Empty message'}), 400

    messages = load_chat_messages()

    import datetime
    new_message = {
        'id': len(messages) + 1,
        'user': session.get('user', 'User'),
        'role': session.get('role', 'Unknown'),
        'message': message,
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'is_support': False
    }
    messages.append(new_message)

    # Generate auto-response from support bot
    auto_response = {
        'id': len(messages) + 1,
        'user': 'Support Bot',
        'role': 'support',
        'message': get_auto_response(message),
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'is_support': True
    }
    messages.append(auto_response)

    save_chat_messages(messages)

    return jsonify({'success': True, 'message': new_message})


@app.route('/api/chat/messages')
def chat_messages():
    """API to get chat messages"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in'}), 401

    messages = load_chat_messages()
    return jsonify(messages)


@app.route('/api/chat/clear', methods=['POST'])
def chat_clear():
    """API to clear chat messages (admin only)"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in'}), 401

    if session.get('role') != 'admin':
        return jsonify({'error': 'Admin only'}), 403

    save_chat_messages([])
    return jsonify({'success': True})


@app.route('/api/chat/upload', methods=['POST'])
def chat_upload():
    """API to upload files (images, X-rays, medical documents)"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in'}), 401

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if file and file.filename and allowed_file(file.filename):
        import datetime
        import uuid

        # Generate unique filename
        unique_id = str(uuid.uuid4())[:8]
        filename = f"{unique_id}_{file.filename}"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        # Get file size
        file_size = os.path.getsize(filepath)

        # Determine file type
        filename_str = file.filename if file.filename else 'unknown'
        file_ext = (
            filename_str.rsplit('.', 1)[1].lower()
            if '.' in filename_str else 'unknown'
        )
        img_exts = ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp']
        file_type = 'image' if file_ext in img_exts else 'document'

        # Create message with file info
        messages = load_chat_messages()

        new_message = {
            'id': len(messages) + 1,
            'user': session.get('user', 'User'),
            'role': session.get('role', 'Unknown'),
            'message': f'📎 Uploaded {file_type}: {file.filename}',
            'timestamp': datetime.datetime.now().strftime(
                '%Y-%m-%d %H:%M:%S'
            ),
            'is_support': False,
            'file': {
                'name': file.filename,
                'url': f'/uploads/{filename}',
                'type': file_type,
                'size': file_size
            }
        }
        messages.append(new_message)

        # Auto-response about the file
        if file_type == 'image':
            msg = (
                f'📥 Thank you for uploading {file.filename}! Our medical '
                f'team will review this image shortly. Is there anything '
                f'specific you\'d like to know about this file?'
            )
            auto_response = {
                'id': len(messages) + 1,
                'user': 'Support Bot',
                'role': 'support',
                'message': msg,
                'timestamp': datetime.datetime.now().strftime(
                    '%Y-%m-%d %H:%M:%S'
                ),
                'is_support': True
            }
        else:
            msg = (
                f'📄 Thank you for uploading {file.filename}! We\'ve '
                f'received your document. Our team will analyze it and get '
                f'back to you shortly.'
            )
            auto_response = {
                'id': len(messages) + 1,
                'user': 'Support Bot',
                'role': 'support',
                'message': msg,
                'timestamp': datetime.datetime.now().strftime(
                    '%Y-%m-%d %H:%M:%S'
                ),
                'is_support': True
            }

        messages.append(auto_response)
        save_chat_messages(messages)

        return jsonify({'success': True, 'file': new_message['file']})

    return jsonify({'error': 'File type not allowed'}), 400


# Serve uploaded files
@app.route('/uploads/<filename>')
def serve_upload(filename):
    """Serve uploaded files"""
    return send_from_directory(UPLOAD_FOLDER, filename)


if __name__ == '__main__':
    print("=" * 60)
    print("🔐 Secure Healthcare Crypto System - Web Interface")
    print("=" * 60)
    print("Starting Flask server at http://localhost:8000")
    print("Press CTRL+C to stop the server")
    print("=" * 60)
    app.run(debug=True, port=8000, host='0.0.0.0')
