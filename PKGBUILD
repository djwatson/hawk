pkgname=hawk
pkgver=0.10
pkgrel=1
pkgdesc='Tracing JIT compiler for Scheme'
arch=('x86_64' 'aarch64')
url='https://github.com/djwatson/hawk'
license=('MIT')
depends=('capstone' 'gcc' 'glibc' 'zstd')
makedepends=('cmake')
source=("$pkgname-v$pkgver.tar.gz::$url/releases/download/v$pkgver/$pkgname-v$pkgver.tar.gz")
sha256sums=('19f95b324f6c464d1234333fb60b35aac1e55737cf904c367d1d639149d11829')

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
