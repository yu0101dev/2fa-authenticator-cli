import sys
import json
import time
import getpass
import base64
import os
import threading
import ctypes
from typing import Dict, Optional
from pyzbar.pyzbar import decode
from PIL import Image
import pyotp
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# --- Configuration ---
STORAGE_FILE = "2fa_storage.dat"
BACKUP_FILE = "2fa_backup.dat"
LOCK_TIMEOUT = 60 * 5  # 5 minutes
MAX_PASSWORD_ATTEMPTS = 5
PASSWORD_ATTEMPTS_FILE = ".password_attempts"
FIXED_SALT = b'\x00' * 16 

# Globals for Session Management
AUTO_LOCK_THREAD = None
LAST_ACTIVITY = time.time()

# -------------------- UX / Visual Helpers --------------------
def clear_screen():
    """Clear terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Print application header."""
    print("\033[1;36m" + "=" * 60 + "\033[0m")
    print("\033[1;34m              🔐  SECURE 2FA AUTHENTICATOR  🔐\033[0m")
    print("\033[1;36m" + "=" * 60 + "\033[0m\n")

def print_success(msg: str):
    print(f"\n\033[1;32m[SUCCESS]\033[0m {msg}")

def print_error(msg: str):
    print(f"\n\033[1;31m[ERROR]\033[0m {msg}")

def print_info(msg: str):
    print(f"\n\033[1;33m[INFO]\033[0m {msg}")

def pause():
    """Wait for user input before continuing."""
    print()
    input("\033[2mPress Enter to continue...\033[0m")

def create_progress_bar(seconds_left: int, total: int = 30, width: int = 20) -> str:
    """Create a visual progress bar."""
    progress = (total - seconds_left) / total
    filled = int(width * progress)
    return '█' * filled + '░' * (width - filled)

def format_countdown(seconds_left: int) -> str:
    """Format countdown with color."""
    if seconds_left > 10:
        return f"\033[32m{seconds_left:2d}s\033[0m"  # Green
    elif seconds_left > 5:
        return f"\033[33m{seconds_left:2d}s\033[0m"  # Yellow
    else:
        return f"\033[31m{seconds_left:2d}s\033[0m"  # Red

def print_code_display(name: str, code: str, seconds_left: int):
    """Print a single TOTP code."""
    formatted_code = f"{code[:3]} {code[3:]}"
    progress_bar = create_progress_bar(seconds_left)
    countdown = format_countdown(seconds_left)
    print(f"\033[1m{name:30}\033[0m: \033[1;37m{formatted_code}\033[0m")
    print(f"{' ':32}[{progress_bar}] {countdown}")
    print()

# -------------------- Security & Encryption --------------------
def get_fixed_key() -> bytes:
    """Derive a fixed key for attempts encryption."""
    kdf = Scrypt(salt=FIXED_SALT, length=32, n=2**14, r=8, p=1)
    return kdf.derive(b'')

def encrypt_attempts(attempts: int) -> bytes:
    key = get_fixed_key()
    aes = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aes.encrypt(nonce, str(attempts).encode(), None)

def decrypt_attempts(blob: bytes) -> int:
    key = get_fixed_key()
    aes = AESGCM(key)
    try:
        return int(aes.decrypt(blob[:12], blob[12:], None).decode())
    except (InvalidTag, ValueError):
        return 0

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def encrypt_data(password: str, data: Dict[str, str]) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    raw = json.dumps(data).encode()
    return salt + nonce + aes.encrypt(nonce, raw, None)

def decrypt_data(password: str, blob: bytes) -> Dict[str, str]:
    if len(blob) < 28: raise ValueError("Data corrupted")
    salt, nonce, enc = blob[:16], blob[16:28], blob[28:]
    key = derive_key(password, salt)
    aes = AESGCM(key)
    try:
        return json.loads(aes.decrypt(nonce, enc, None).decode())
    except (InvalidTag, ValueError):
        raise ValueError("Invalid Password")

# -------------------- Storage Logic --------------------
def load_storage(password: str) -> Dict[str, str]:
    if not os.path.exists(STORAGE_FILE):
        return {}
    try:
        with open(STORAGE_FILE, "rb") as f:
            return decrypt_data(password, f.read())
    except OSError:
        raise ValueError("File access error")

def save_storage(password: str, data: Dict[str, str]):
    try:
        with open(STORAGE_FILE, "wb") as f:
            f.write(encrypt_data(password, data))
    except OSError:
        print_error("Failed to save data to disk.")

def scrub_memory(data):
    """Attempt to clear sensitive data from memory."""
    if isinstance(data, dict):
        for key in list(data.keys()):
            del data[key]
    elif isinstance(data, list):
        del data[:]

# -------------------- Attempt Limiting --------------------
def check_password_attempts() -> bool:
    if not os.path.exists(PASSWORD_ATTEMPTS_FILE): return True
    try:
        with open(PASSWORD_ATTEMPTS_FILE, 'rb') as f:
            if decrypt_attempts(f.read()) >= MAX_PASSWORD_ATTEMPTS:
                print_error(f"Too many failed attempts. Account locked.")
                return False
    except:
        reset_password_attempts()
    return True

def record_failed_attempt():
    attempts = 0
    if os.path.exists(PASSWORD_ATTEMPTS_FILE):
        try:
            with open(PASSWORD_ATTEMPTS_FILE, 'rb') as f:
                attempts = decrypt_attempts(f.read())
        except: pass
    attempts += 1
    with open(PASSWORD_ATTEMPTS_FILE, 'wb') as f:
        f.write(encrypt_attempts(attempts))
    print_error(f"Incorrect password. Attempts remaining: {MAX_PASSWORD_ATTEMPTS - attempts}")

def reset_password_attempts():
    if os.path.exists(PASSWORD_ATTEMPTS_FILE):
        os.remove(PASSWORD_ATTEMPTS_FILE)

# -------------------- Core Features --------------------
def add_manual(password: str):
    """Add account via Manual Entry."""
    print_info("Manual Entry Mode")
    print("\033[90mTip: The Secret Key is usually a string of letters provided by the website (e.g., JBSW Y3DP...)\033[0m")
    
    label = input("\n1. Enter Account Name (e.g. Gmail, Discord): ").strip()
    if not label: return print_error("Label cannot be empty.")
    
    secret = input("2. Enter Secret Key: ").strip().upper().replace(" ", "")
    
    try:
        # Validate Secret
        pyotp.TOTP(secret).now()
    except:
        return print_error("Invalid Base32 Secret Key.")

    storage = load_storage(password)
    label = label.replace(":", "_")
    
    if label in storage:
        if input(f"Account '{label}' exists. Overwrite? (y/N): ").lower() != 'y': return

    storage[label] = secret
    save_storage(password, storage)
    print_success(f"Account '{label}' added successfully!")
    scrub_memory(storage)

def add_qr(password: str):
    """Add account via QR Image."""
    print_info("QR Import Mode")
    img_path = input("Enter path to QR code image (e.g., screenshot.png): ").strip()
    
    if not os.path.exists(img_path):
        return print_error("File not found.")
    
    try:
        decoded = decode(Image.open(img_path))
        if not decoded: return print_error("No QR code found in image.")
    except Exception as e:
        return print_error(f"Image error: {e}")

    storage = load_storage(password)
    count = 0
    
    for obj in decoded:
        uri = obj.data.decode()
        if "otpauth://totp/" not in uri: continue
        
        try:
            # Parse URI
            parsed = pyotp.parse_uri(uri)
            label = f"{parsed.issuer}_{parsed.name}" if parsed.issuer else parsed.name
            secret = parsed.secret
            
            storage[label] = secret
            count += 1
            print(f"   > Found: {label}")
        except:
            print(f"   > Skipping invalid URI")

    if count > 0:
        save_storage(password, storage)
        print_success(f"Imported {count} accounts.")
        if input("Delete QR image for security? (y/N): ").lower() == 'y':
            os.remove(img_path)
            print_success("Image deleted.")
    else:
        print_info("No valid TOTP accounts found in QR.")
    scrub_memory(storage)

def display_codes(password: str):
    """Live Dashboard."""
    storage = load_storage(password)
    if not storage: return print_info("No accounts. Add one first!")
    
    print("\033[1mStarting Dashboard... (Press Ctrl+C to Exit)\033[0m")
    time.sleep(1)
    
    try:
        while True:
            update_activity()
            clear_screen()
            print_header()
            
            now = time.time()
            remaining = 30 - (int(now) % 30)
            
            sorted_accounts = sorted(storage.items())
            
            for label, secret in sorted_accounts:
                try:
                    totp = pyotp.TOTP(secret)
                    code = totp.now()
                    print_code_display(label, code, remaining)
                except:
                    print(f"{label}: Error generating code")

            print("\033[2m" + "-" * 60 + "\033[0m")
            print("\033[2mPress Ctrl+C to return to menu\033[0m")
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping...")

def list_accounts(password: str):
    storage = load_storage(password)
    if not storage: return print_info("Vault is empty.")
    
    print(f"\n\033[1mStored Accounts ({len(storage)}):\033[0m")
    print("-" * 30)
    for i, acc in enumerate(sorted(storage.keys()), 1):
        print(f"{i}. {acc}")
    print("-" * 30)

def change_password_flow(current_password: str):
    print_info("Security Check: Verify current password")
    
    # 1. Re-verify old password
    verify = getpass.getpass("Enter OLD Master Password: ")
    if verify != current_password:
        return print_error("Wrong password. Cannot proceed.")

    # 2. Set new password
    print("\n\033[1mSet NEW Master Password\033[0m")
    new_p = getpass.getpass("New Password: ")
    if len(new_p) < 8:
        print_error("Password too short (min 8 chars).")
        return
        
    confirm = getpass.getpass("Confirm New Password: ")
    if new_p != confirm:
        return print_error("Passwords do not match.")

    # 3. Re-encrypt data
    storage = load_storage(current_password)
    save_storage(new_p, storage)
    print_success("Master password changed successfully!")
    return new_p

# -------------------- Setup & Main Loop --------------------
def update_activity():
    global LAST_ACTIVITY
    LAST_ACTIVITY = time.time()

def auto_lock():
    while True:
        if time.time() - LAST_ACTIVITY > LOCK_TIMEOUT:
            print("\n\n\033[31m[TIMEOUT] Session locked due to inactivity.\033[0m")
            os._exit(0)
        time.sleep(10)

def setup_wizard():
    """First run experience."""
    clear_screen()
    print_header()
    print("\033[1;33mWelcome! It looks like this is your first time running the app.\033[0m")
    print("Let's set up your secure vault.\n")
    
    while True:
        pwd = getpass.getpass("1. Create a Master Password: ")
        if len(pwd) < 8:
            print_error("Password must be at least 8 characters.")
            continue
            
        conf = getpass.getpass("2. Confirm Master Password: ")
        if pwd != conf:
            print_error("Passwords do not match. Try again.")
            continue
            
        # Create empty storage
        save_storage(pwd, {})
        print_success("Vault initialized! You can now log in.")
        time.sleep(2)
        return

def interactive_menu():
    # 1. Check if setup needed
    if not os.path.exists(STORAGE_FILE):
        setup_wizard()

    # 2. Login
    clear_screen()
    print_header()
    
    if not check_password_attempts():
        return

    password = ""
    while True:
        try:
            password = getpass.getpass("\033[1mLogin (Master Password): \033[0m")
            load_storage(password) # Verify
            reset_password_attempts()
            print_success("Access Granted.")
            time.sleep(0.5)
            break
        except ValueError:
            record_failed_attempt()
            if not check_password_attempts(): return
        except KeyboardInterrupt:
            print("\nGoodbye.")
            return

    # 3. Start Auto-lock
    threading.Thread(target=auto_lock, daemon=True).start()

    # 4. Menu Loop
    while True:
        update_activity()
        clear_screen()
        print_header()
        print("\033[1mMAIN MENU\033[0m")
        print(" 1. 🔍 Show 2FA Codes")
        print(" 2. ➕ Add Account (Manual Secret)")
        print(" 3. 📷 Add Account (QR Image)")
        print(" 4. 📋 List All Accounts")
        print(" 5. ❌ Remove Account")
        print(" 6. 🔐 Change Master Password")
        print(" 7. 💾 Export/Import Backup")
        print(" 8. 🚪 Exit")
        print("\033[90m" + "-" * 60 + "\033[0m")
        
        choice = input("Select option: ").strip()
        update_activity()

        if choice == '1':
            display_codes(password)
        elif choice == '2':
            add_manual(password)
            pause()
        elif choice == '3':
            add_qr(password)
            pause()
        elif choice == '4':
            list_accounts(password)
            pause()
        elif choice == '5':
            key = input("Enter account name to remove: ")
            s = load_storage(password)
            if key in s:
                if input("Are you sure? (y/N): ").lower() == 'y':
                    del s[key]
                    save_storage(password, s)
                    print_success("Removed.")
            else:
                print_error("Account not found.")
            pause()
        elif choice == '6':
            new_pass = change_password_flow(password)
            if new_pass: password = new_pass
            pause()
        elif choice == '7':
            print("\n1. Export Backup\n2. Import Backup")
            sub = input("Choice: ")
            if sub == '1':
                save_storage(password, load_storage(password)) # Re-save to backup
                try:
                    with open(STORAGE_FILE, 'rb') as src, open(BACKUP_FILE, 'wb') as dst:
                        dst.write(src.read())
                    print_success(f"Backup saved to {BACKUP_FILE}")
                except: print_error("Backup failed.")
            elif sub == '2':
                if os.path.exists(BACKUP_FILE):
                    if input("This will overwrite current data. Continue? (y/N): ").lower() == 'y':
                        try:
                            with open(BACKUP_FILE, 'rb') as src, open(STORAGE_FILE, 'wb') as dst:
                                dst.write(src.read())
                            print_success("Restored.")
                        except: print_error("Restore failed.")
                else:
                    print_error("No backup file found.")
            pause()
        elif choice == '8':
            print("\n\033[32mStay Secure! 👋\033[0m")
            break
        else:
            print_error("Invalid option")
            time.sleep(1)

# -------------------- CLI Mode --------------------
def cli_mode():
    if len(sys.argv) < 2:
        # Default to interactive if no args
        interactive_menu()
        return

    command = sys.argv[1]
    
    if not os.path.exists(STORAGE_FILE):
        print_error("Vault not initialized! Run without arguments first to setup.")
        return

    password = getpass.getpass("Master Password: ")
    try:
        load_storage(password)
    except ValueError:
        print_error("Wrong password.")
        return

    if command == "get":
        display_codes(password)
    elif command == "add":
        print_info("Use interactive menu for easier adding.")
    else:
        print_info(f"Unknown command: {command}")

if __name__ == "__main__":
    try:
        cli_mode()
    except KeyboardInterrupt:
        print("\n\nExiting...")
    except Exception as e:
        print_error(f"Unexpected error: {e}")
