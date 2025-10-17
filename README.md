# Kripton Authenticator
Kripton Authenticator is a command-line-based two-factor authentication (2FA) application written in Rust. It supports both Time-based One-Time Passwords (TOTP) and HMAC-based One-Time Passwords (HOTP), allowing users to securely manage their 2FA codes. The application encrypts all data locally using AES-256-GCM and derives encryption keys with Argon2id, ensuring high security for stored secrets.

## Features

**TOTP and HOTP Support:** Generate one-time passwords for both time-based and counter-based authentication.

**Secure Storage:** Encrypts secrets using AES-256-GCM with keys derived from a master password via Argon2id.

**Clipboard Integration:** Automatically copy generated OTP codes to the clipboard (optional).

**Backup and Restore:** Export and import accounts in plain text, encrypted, or otpauth:// URI format for QR code compatibility.

**Interactive CLI:** User-friendly interface to add, edit, delete, and manage accounts.

**Account Management:** Rename accounts, update secrets, modify parameters (type, algorithm, digits, step/counter), and add notes.

**Error Handling:** Robust error handling with custom error types for I/O, cryptographic, and user input issues.

**Secure File Handling:** Temporary files are securely deleted, and store files have restricted permissions (0o600).

## Installation

### Prerequisites

1. Rust
2. Cargo (included with Rust)

### Arch Linux (AUR)
You can install it using an AUR helper like ```yay```:
```bash
yay -S kripton-authenticator
```
or
```bash
yay -S kripton-authenticator-bin
```

### Build from Source

1. Clone the repository:
```bash
git clone https://github.com/clauderarch/kripton-authenticator.git
cd kripton-authenticator
```

2. Build the application:
```bash
cargo build --release
```

3. Run the application:
```bash
./target/release/kripton-authenticator
```

### Dependencies
The application uses the following Rust crates:

```aes-gcm:``` For AES-256-GCM encryption.

```argon2:``` For secure key derivation.

```base32:``` For Base32 encoding/decoding.

```chrono:``` For timestamp handling in TOTP.

```hmac, sha1, sha2:``` For HMAC-based OTP generation.

```serde:``` For JSON serialization/deserialization.

```arboard:``` For clipboard integration.

```rpassword:``` For secure password input.

```zeroize:``` For securely zeroing sensitive data.

```thiserror:``` For custom error handling.

```url``` and ```urlencoding:``` For parsing and encoding otpauth:// URIs.

Run ```cargo install``` to automatically fetch and install dependencies.

## Usage

### Run the Application:
```bash
./target/release/kripton-authenticator
```


### Set a Master Password:

On first run, you'll be prompted to set a master password. This password is used to encrypt and decrypt your stored accounts.
Warning: If you forget your master password, your accounts cannot be recovered. Use the backup feature to store your data securely.


### Main Menu Options:

**Add account:** Add a new TOTP or HOTP account with a custom name, secret, algorithm (SHA-1, SHA-256, SHA-512), and digits (6 or 8).

**Get code:** Generate an OTP code for a specific account. Optionally copies to clipboard.

**Edit account:** Modify account name, secret, parameters, or notes.

**Delete account:** Remove an account from the store.

**List accounts:** Display all saved accounts with their type, algorithm, and digits.

**Backup codes:** Export accounts in plain text, encrypted, or ```otpauth://``` URI format.

**Restore codes:** Import accounts from a backup file (plain text, encrypted, or URI format).

**Settings:** Toggle auto-copy to clipboard, hide OTP codes, or change the master password.

**View note:** Display the note associated with an account.

**Exit:** Close the application.


### Backup and Restore:

**Plain Text Backup:** Exports accounts in a readable format (unencrypted, use with caution).
**Encrypted Backup:** Exports accounts encrypted with a separate backup password.
**URI Backup:** Exports accounts as ```otpauth://``` URIs for QR code generation.
**Restore:** Imports accounts from any of the above formats, skipping duplicates.


## Security Considerations

**Master Password:** The master password is critical for accessing your accounts. Store it securely or use the backup feature.

**Encrypted Storage:** All accounts are stored in an encrypted file (auth_store_<hash>.enc) in the user's data directory.

**Secure Deletion:** When changing the master password or deleting files, the application overwrites old files with random data before deletion.

**Clipboard:** Codes copied to the clipboard are not cleared automatically. Be cautious when using auto-copy on shared systems.

**Backup Files:** Plain text and URI backups are unencrypted. Store them securely to prevent unauthorized access.

## Directory Structure

**Source Code:** src/main.rs contains the main application logic.

**Data Storage:** Encrypted store files are saved in the platform-specific data directory (e.g., ~/.local/share/KriptonAuthenticator/ on Linux).

**Temporary Files:** Temporary files (.tmp) are used during encryption and securely deleted after successful operations.

## Contributing
Contributions are welcome! If you have suggestions or want to report an issue, please open an issue or submit a pull request.

## License
This project is licensed under the **[GPL-3.0]** - see the LICENSE file for details.
