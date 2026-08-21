pkgname=hawk
pkgver=0.9
pkgrel=1
pkgdesc='Tracing JIT compiler for Scheme'
arch=('x86_64' 'aarch64')
url='https://github.com/djwatson/hawk'
license=('MIT')
depends=('capstone' 'gcc' 'glibc' 'zstd')
makedepends=('cmake')
source=("$pkgname-v$pkgver.tar.gz::$url/releases/download/v$pkgver/$pkgname-v$pkgver.tar.gz")
sha256sums=('dfb6f99737e7cbdeacbc85d04509056e7d391276d7a5c826ead13189bb8fc41e')

build() {
  cmake -S "$pkgname-v$pkgver" -B build \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
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
