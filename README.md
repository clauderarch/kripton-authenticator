Kripton Authenticator is a terminal-based TOTP app.

Depends: rust, git, glibc

Installation:
On Arch Linux "yay -S kripton-authenticator" or "paru -S kripton-authenticator"

If you don't have yay;
sudo pacman -S rust git glibc

git clone https://github.com/clauderarch/kripton-authenticator.git

cd kripton-authenticator

cargo run

Usage:
Enter a password and thats it. Don't forget backup your TOTP codes.
