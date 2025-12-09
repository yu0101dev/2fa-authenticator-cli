# 🔐 Secure CLI 2FA Authenticator: Your Desktop Vault

> ***The Scenario:*** You're trying to log into a service, but your phone is charging across the room (or worse, died!) and you need that quick 2FA code.
>
><p align="center">
>  <img src="https://i.ibb.co/6cb75XTq/a-Vbj-Xwv-700bwp.webp" alt="Screenshot of the Secure CLI 2FA Authenticator tool in use" width="40%"/>
></p>
>
> ***The Solution:*** This tool is your **secure, encrypted desktop backup** for your Google Authenticator codes, making sure you always have access when you need it. It’s a robust, command-line authenticator built with security and user experience in mind.


A powerful, Python-based Desktop Authenticator that allows you to manage **Time-based One-Time Passwords (TOTP)** securely from your terminal. It features military-grade encryption, auto-locking mechanisms, and a specialized "First Run" wizard.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-green.svg)
![Security](https://img.shields.io/badge/encryption-AES--GCM-red.svg)


<p align="center">
  <img src="https://i.ibb.co/hv3xMPK/2fa-1.png"  width="60%"/>
</p>

<p align="center">
  <img src="https://i.ibb.co/cS4nTv2c/2fa-2.png"  width="60%"/>
</p>


## ✨ Features

* **AES-256-GCM Encryption:** All secrets are encrypted at rest with industry-standard, authenticated encryption.
* **Scrypt Key Derivation:** Uses a memory-hard function to convert your password into an encryption key, making the vault **highly resistant to brute-force attacks**.
* **QR Code Support:** Import accounts directly by scanning screenshots of QR codes.
* **Live Dashboard:** Real-time, color-coded countdowns for your OTP codes.
* **Auto-Lock:** Automatically secures the session after **5 minutes of inactivity**.
* **Good User Experience:** Provides clear, colored feedback on every action (Success, Error, Info, Action prompts).

## 📦 Installation & Setup

It is recommended to run this tool in a virtual environment.

### 1. Clone the repository
```bash
git clone https://github.com/yu0101dev/2fa-authenticator-cli.git
cd secure-2fa-cli
```

### 2. Set up Virtual Environment
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Mac/Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install pyotp cryptography Pillow pyzbar
# OR using the requirements file
pip install -r requirements.txt
```

---

## 🚀 How to Run & Use the Vault

### 1. Interactive Menu (Recommended)

Run the script without any arguments. If it's the first time, the **Setup Wizard** will launch, requiring you to set and confirm a strong Master Password.

```bash
python secure-2fa-cli.py
```

### 2. Command Line Interface (CLI) Mode

For power users or quick lookups, you can pass commands directly to the script. This skips the main menu and executes a single action, but will still prompt for the Master Password.

| Command | Usage Example | Description |
| :--- | :--- | :--- |
| **get** | `python secure-2fa-cli.py get` | Launches the live dashboard showing all 2FA codes. |
| **get** (filtered) | `python secure-2fa-cli.py get "Google"` | Filters and shows only codes matching the keyword. |
| **list** | `python secure-2fa-cli.py list` | Prints all stored account names. |
| **remove** | `python secure-2fa-cli.py remove "AccountName"` | Prompts for confirmation and deletes the specified account. |

---

## 💾 Export & Import Backup (Critical for Data Safety)

Your secrets are stored locally in the **encrypted vault** file, `2fa_storage.dat`. To back this up, you must use the menu option **7. Export/Import Backup**.

### **How to Export (Backup)**
1. Select option **7** from the main menu.
2. Select option **1. Export Backup**.
3. The script creates a copy of the encrypted vault named `2fa_backup.dat`.

**Action:** `python secure-2fa-cli.py` -> Menu **7** -> Sub-menu **1**

### **How to Import (Restore)**
1. Select option **7** from the main menu.
2. Select option **2. Import Backup**.
3. **WARNING:** This action will **overwrite** your current `2fa_storage.dat` with the data from `2fa_backup.dat`. You will be prompted to confirm this critical action.

**Action:** `python secure-2fa-cli.py` -> Menu **7** -> Sub-menu **2**

---

## 🛡️ Security Deep Dive

### **How Secure is this Version?**
The tool utilizes modern, audited cryptographic standards:

1.  **Cipher:** **AES-256-GCM** (Authenticated Encryption). This provides confidentiality and ensures data integrity—meaning a hacker cannot tamper with the file without the system detecting it.
2.  **Key Derivation Function (KDF):** **Scrypt**. This is a **memory-hard** function, designed to make password-guessing (brute-forcing) extremely expensive in terms of both time and hardware, significantly improving security over weaker KDFs.
3.  **Session Security:** The **Auto-Lock** feature ensures that even if you leave your terminal open, your vault session will lock after 5 minutes of inactivity, requiring the Master Password to resume.

### **Educational: How TOTP Works**

**TOTP** (Time-based One-Time Password) is the standard algorithm used by most modern services. It is an ingenious concept that relies on three elements to generate the exact same code on any device:

1.  **The Shared Secret:** The long alphanumeric key exchanged when you scan a QR code.
2.  **The Time:** The current Unix time, divided into standard **30-second windows**.
3.  **The Algorithm:** HMAC-SHA1.

The script combines the **Secret** and the current **Time Window** to produce a deterministic, 6-digit code. Since this is an open standard, your script and the service (e.g., Google's server) generate the identical code simultaneously.
