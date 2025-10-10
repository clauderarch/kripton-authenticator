🧩 Kripton Authenticator

Kripton Authenticator is a terminal-based TOTP (Time-based One-Time Password) application.
It allows you to securely manage two-factor authentication codes in a simple and open-source way.

🔧 Dependencies;
rust
git
glibc

🚀 Installation:
On Arch Linux:
"yay -S kripton-authenticator" or "paru -S kripton-authenticator"

Manual Installation:
sudo pacman -S rust git glibc,
git clone https://github.com/clauderarch/kripton-authenticator.git,
cd kripton-authenticator,
cargo run

💡 Usage

Run the application and enter a password when prompted.
This password is used to protect your TOTP codes.

⚠️ Warning: Make sure to back up your TOTP codes.
If you lose your password or data, your codes cannot be recovered.

🛠️ Features

Lightweight and fast terminal interface

Secure implementation written in Rust

Fully open-source.
