# Kripton Authenticator

**Kripton Authenticator** is a secure, command-line Time-based One-Time Password (TOTP) generator and secret storage utility written in Rust, primarily designed for **Linux** environments, with a focus on security and privacy. It allows you to manage and generate 2FA codes for your accounts directly from your terminal, with all data protected by strong, modern cryptography.

## Features

* **Strong Encryption:** Secrets are stored locally using **AES-256 GCM** encryption.
* **Secure Key Derivation:** Uses **Argon2id** (with high memory/time parameters) to derive the encryption key from your master password, offering robust protection against brute-force attacks.
* **TOTP Generation:** Generates industry-standard 6-digit TOTP codes, compatible with most 2FA-protected services.
* **Secret Management:** Easily add, list, and delete your TOTP accounts.
* **Data Sanitization:** Utilizes the `zeroize` crate to securely clear sensitive data from memory.
* **Linux-Optimized:** Stores data in the standard Linux user data directory (`$XDG_DATA_HOME` or `~/.local/share/KriptonAuthenticator`) with secure file permissions (`0o600`).

## Installation

### Prerequisites

You need to have [Rust](https://www.rust-lang.org/tools/install) and [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) installed on your system to build the application.

### Arch Linux (AUR)

You can install it using an AUR helper like `yay`:

```bash
yay -S kripton-authenticator
```
**or**
```bash
yay -S kripton-authenticator-bin
```
### Build from Source (Recommended for other Linux Distributions)

**1. Clone the repository:**
```bash
git clone https://aur.archlinux.org/kripton-authenticator.git
cd kripton-authenticator
```

**2. Build the project:**
```bash
cargo build --release
```

**3. Install the executable to your system's path. This allows you to run the program from anywhere by typing kripton-authenticator:**
 Ensure ~/.local/bin is in your PATH
```bash
cp target/release/kripton-authenticator ~/.local/bin/
```

## Usage
The first time you run the application, it will prompt you to set a master password. This password is used to encrypt your entire secret store.
```bash
kripton-authenticator
```
### Main Menu and Commands
The application is run entirely through a simple command-line menu:
| Choice | Command | Description |
| :---: | :--- | :--- |
| **1** | **Add New Account** | Prompts for the account name and the Base32 secret key. |
| **2** | **Generate TOTP Code** | Prompts for the account name and displays the current 6-digit code and the countdown to the next code. |
| **3** | **Edit Accounts** | Allows to you change name and Base32 code of a account. |
| **4** | **Delete Accounts** | Permanently removes an account from the encrypted store. |
| **5** | **List Saved Accounts** | Displays a list of all account names stored. |
| **6** | **Backup Codes** | Creates a portable copy of your secret store (can be encrypted or plaintext). |
| **7** | **Restore Codes** | Imports accounts from a backup file. |
| **8** | **Exit** | Closes the application. |

## Security and Data Location
**Encryption Scheme:** *Argon2id* (Key Derivation) + *AES-256 GCM* (Encryption).

**Data File:** The encrypted secret store is saved in the directory specified by the XDG Base Directory Specification.

**Permissions:** The application attempts to set restrictive file permissions (0o600) on the secret store file to prevent unauthorized access.

## License
This project is licensed under the [GPL-3.0] - see the LICENSE file for details.

## Contributing
Contributions are welcome! If you have suggestions or want to report an issue, please open an issue or submit a pull request.
