# Maintainer: Your Name <you@example.com>

pkgname=kripton-authenticator
pkgver=0.6.0
pkgrel=1
pkgdesc="A terminal-based two-factor authentication tool written in Rust"
arch=('x86_64')
url="https://github.com/yourusername/kripton-authenticator"
license=('MIT')
depends=('glibc')
makedepends=('cargo')
source=(
  "git+$url.git"
  "kripton-authenticator.desktop"
  "assets/kripton.png"
)
sha256sums=('SKIP' 'SKIP' 'SKIP')

build() {
  cd "$srcdir/$pkgname"
  cargo build --release --locked
}

package() {
  cd "$srcdir/$pkgname"

  install -Dm755 "target/release/$pkgname" \
    "$pkgdir/usr/bin/$pkgname"

  install -Dm644 "$srcdir/kripton-authenticator.desktop" \
    "$pkgdir/usr/share/applications/kripton-authenticator.desktop"

  install -Dm644 "$srcdir/assets/kripton.png" \
    "$pkgdir/usr/share/icons/hicolor/64x64/apps/kripton.png"
}

