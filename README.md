# Kripton Authenticator

```
 $$\   $$\                  $$$$$$\              $$\     $$\       
 $$ | $$  |                $$  __$$\             $$ |    $$ |      
 $$ |$$  /  $$$$$$\        $$ /  $$ |$$\   $$\ $$$$$$\   $$$$$$$\  
 $$$$$  /  $$  __$$\       $$$$$$$$ |$$ |  $$ |\_$$  _|  $$  __$$\ 
 $$  $$<   $$ |  \__|      $$  __$$ |$$ |  $$ |  $$ |    $$ |  $$ |
 $$ |\$$\  $$ |            $$ |  $$ |$$ |  $$ |  $$ |$$\ $$ |  $$ |
 $$ | \$$\ $$ |            $$ |  $$ |\$$$$$$  |  \$$$$  |$$ |  $$ |
 \__|  \__|\__|            \__|  \__| \______/    \____/ \__|  \__|
```

**A secure, terminal-based two-factor authentication (2FA) code generator**

## Overview

Kripton Authenticator is a command-line authenticator application that provides secure storage and generation of Time-based One-Time Passwords (TOTP) and HMAC-based One-Time Passwords (HOTP). Built with security in mind, it uses industry-standard encryption algorithms to protect your 2FA secrets locally.

## Features

- **Military-Grade Encryption**: AES-256-GCM encryption with Argon2id key derivation
- **TOTP & HOTP Support**: Generate both time-based and counter-based one-time passwords
- **Multiple Hash Algorithms**: SHA-1, SHA-256, and SHA-512 support
- **Auto-Copy to Clipboard**: Optionally copy codes automatically (with configurable privacy mode)
- **Import/Export**: Backup and restore your accounts with encrypted or plain text formats
- **otpauth:// URI Support**: Import accounts via QR code URIs
- **Smart Autocomplete**: Intelligent account name suggestions with fuzzy matching
- **Secure by Design**: 
  - Zero-knowledge architecture (no cloud sync)
  - Secure password-based file encryption
  - Secure deletion of old data
  - Memory-safe operations with zeroization
- **Privacy Features**: Option to hide OTP codes on screen while copying to clipboard
- **Notes Support**: Add optional notes to your accounts

## Installation

### Prerequisites

- Rust
- Cargo package manager

### Arch Linux (AUR)

You can install it using an AUR helper like ```yay```:
```bash
yay -S kripton-authenticator
```
or
```bash
yay -S kripton-authenticator-bin
```

### From Source

```bash
# Clone the repository
git clone https://github.com/clauderarch/kripton-authenticator.git
cd kripton-authenticator

# Build and install
cargo build --release
```

## Usage

### First Launch

On first launch, you'll be prompted to set a master password:

**Important**: If you forget your master password, there is no way to recover your data. Use the backup feature regularly!

### Main Menu Options

1. **Get Code** - Generate an OTP code for an account
2. **Add Account** - Add a new 2FA account (manual or via URI)
3. **List Accounts** - View all saved accounts
4. **Edit Account** - Modify account settings
5. **Delete Account** - Remove an account
6. **View Note** - Display the note for an account
7. **Backup Codes** - Export your accounts
8. **Restore Codes** - Import accounts from backup
9. **Settings** - Configure application preferences
10. **Exit** - Close the application

### Adding an Account

#### Manual Entry
```
1. Select "Add account"
2. Choose "Manual input"
3. Enter account name (e.g., "GitHub:username")
4. Enter Base32 secret key
5. Configure OTP parameters (type, algorithm, digits, step/counter)
```

#### Via otpauth:// URI
```
1. Select "Add account"
2. Choose "otpauth URI"
3. Paste the otpauth:// URL from your QR code
4. Optionally modify the account name
```

### Backup Formats

Kripton Authenticator supports three backup formats:

1. **Plain Text (.txt)**: Unencrypted, human-readable format
2. **Encrypted Backup (.enc)**: Password-protected encrypted backup, this feature only supports .enc files created by Kripton Authenticator.
3. **otpauth:// URI List (.txt)**: QR-code compatible format

## Technical Details

### Encryption Specifications

- **Symmetric Encryption**: AES-256-GCM
- **Key Derivation**: Argon2id
  - Memory: 128 MB
  - Iterations: 3
  - Parallelism: 4
- **Nonce**: 12 bytes (randomly generated per encryption)
- **Salt**: 16 bytes (unique per store file)

### Security Features

- **Password-Derived File Naming**: Store files are named based on a hash of your password
- **Secure Memory Handling**: Sensitive data is zeroized after use
- **Atomic File Operations**: Safe concurrent access protection
- **Permission Hardening**: Store files are created with 0600 permissions (Unix)

### Supported OTP Parameters

- **Types**: TOTP, HOTP
- **Algorithms**: SHA-1, SHA-256, SHA-512
- **Digits**: 6 or 8
- **Step (TOTP)**: Configurable (default: 30 seconds)
- **Counter (HOTP)**: Auto-incrementing with user confirmation

## Data Storage

Data is stored locally in platform-specific directories:

- **Linux**: `~/.local/share/KriptonAuthenticator/`

Each password creates a unique encrypted store file named: `auth_store_<hash>.enc`

## Security Best Practices

1. **Use a Strong Master Password**: Your master password is the only key to your data
2. **Regular Backups**: Keep encrypted backups in a secure location
3. **Physical Security**: Ensure your device is physically secure
4. **Unique Passwords**: Don't reuse your master password elsewhere
5. **Secure Deletion**: The app uses secure deletion when removing old store files

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the GPL-3.0 License

## Disclaimer

This software is provided "as is" without warranty of any kind. While every effort has been made to ensure security, users should:

- Maintain secure backups of their data
- Use at their own risk
- Understand that forgotten passwords cannot be recovered
- Review the code before trusting it with sensitive data
