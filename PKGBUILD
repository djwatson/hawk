# Maintainer: Dave Watson <dade.watson at gmail dot com>

pkgname=hawk
pkgver=0.11
pkgrel=1
pkgdesc='Tracing JIT compiler for Scheme'
arch=('x86_64' 'aarch64')
url='https://github.com/djwatson/hawk'
license=('MIT')
depends=('capstone' 'gcc' 'glibc' 'zstd')
makedepends=('cmake')
source=("$pkgname-v$pkgver.tar.gz::$url/releases/download/v$pkgver/$pkgname-v$pkgver.tar.gz")
sha256sums=('27a5cebb94a5faec16d7213df9318dd952fbbc341145f45d817349c1ea7431c4')

build() {
  cmake -S "$pkgname-v$pkgver" -B build \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DCMAKE_INSTALL_LIBDIR=lib
  cmake --build build
}

check() {
  ctest --test-dir build --output-on-failure
}

package() {
  DESTDIR="$pkgdir" cmake --install build
  install -Dm644 "$pkgname-v$pkgver/LICENSE" \
    "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
