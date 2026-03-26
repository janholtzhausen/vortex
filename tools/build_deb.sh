#!/bin/bash
# Build a .deb package for vortex.
# Usage: tools/build_deb.sh [version]
# Default version is derived from git describe (e.g. 0.2.1).
# Output: vortex_<version>_amd64.deb in the repo root.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build-release"

latest_local_pkg_version() {
    find "$REPO_ROOT" -maxdepth 1 -type f -name 'vortex_*_amd64.deb' -printf '%f\n' 2>/dev/null \
        | sed -n 's/^vortex_\(.*\)_amd64\.deb$/\1/p' \
        | sort -V \
        | tail -n 1
}

default_version() {
    local git_version=""
    local pkg_version=""

    git_version="$(git -c safe.directory="$REPO_ROOT" -C "$REPO_ROOT" describe --tags --abbrev=0 2>/dev/null \
        | sed 's/^v//')"
    pkg_version="$(latest_local_pkg_version)"

    if [ -n "$git_version" ] && [ -n "$pkg_version" ]; then
        printf '%s\n%s\n' "$git_version" "$pkg_version" | sort -V | tail -n 1
    elif [ -n "$pkg_version" ]; then
        printf '%s\n' "$pkg_version"
    elif [ -n "$git_version" ]; then
        printf '%s\n' "$git_version"
    else
        echo "Unable to determine package version." >&2
        echo "Pass an explicit version: bash tools/build_deb.sh <version>" >&2
        exit 1
    fi
}

VERSION="${1:-$(default_version)}"
PKG="vortex_${VERSION}_amd64"
STAGING="/tmp/${PKG}"
OPENSSL_ROOT_DIR="${OPENSSL_ROOT_DIR:-/opt/openssl-4.0}"
NGTCP2_BUILD_DIR="${NGTCP2_BUILD_DIR:-/opt/ngtcp2/build}"
NGHTTP3_BUILD_DIR="${NGHTTP3_BUILD_DIR:-/opt/nghttp3/build}"
NGTCP2_SRC_DIR="${NGTCP2_SRC_DIR:-/tmp/ngtcp2-1.16.0}"
NGHTTP3_SRC_DIR="${NGHTTP3_SRC_DIR:-/tmp/nghttp3-1.8.0}"
VORTEX_DEB_MARCH="${VORTEX_DEB_MARCH:-znver3}"

echo "==> Building vortex .deb  version=${VERSION} march=${VORTEX_DEB_MARCH}"

# ---- 1. Compile ----
cmake -S "$REPO_ROOT" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DVORTEX_MARCH="$VORTEX_DEB_MARCH" \
    -DFORCE_OPENSSL_BUNDLED=ON \
    -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT_DIR" \
    -DNGTCP2_BUILD_DIR="$NGTCP2_BUILD_DIR" \
    -DNGHTTP3_BUILD_DIR="$NGHTTP3_BUILD_DIR" \
    -DNGTCP2_SRC_DIR="$NGTCP2_SRC_DIR" \
    -DNGHTTP3_SRC_DIR="$NGHTTP3_SRC_DIR" \
    -Wno-dev -DCMAKE_EXPORT_COMPILE_COMMANDS=OFF 2>/dev/null
make -C "$BUILD_DIR" -j"$(nproc)"

# ---- 2. Stage package tree ----
rm -rf "$STAGING"
install -d "$STAGING/DEBIAN"
install -d "$STAGING/usr/bin"
install -d "$STAGING/usr/share/vortex"
install -d "$STAGING/usr/lib/vortex"
install -d "$STAGING/etc/vortex"
install -d "$STAGING/lib/systemd/system"
install -d "$STAGING/etc/ld.so.conf.d"

# Binary — strip debug info and set rpath to the .deb install location
install -m 755 "$BUILD_DIR/vortex" "$STAGING/usr/bin/vortex"
strip --strip-unneeded "$STAGING/usr/bin/vortex"
patchelf --set-rpath /usr/lib/vortex "$STAGING/usr/bin/vortex" 2>/dev/null || \
    chrpath -r /usr/lib/vortex "$STAGING/usr/bin/vortex" 2>/dev/null || true

# BPF object
install -m 644 "$BUILD_DIR/vortex_xdp.bpf.o" "$STAGING/usr/share/vortex/vortex_xdp.bpf.o"

# Bundled OpenSSL 4.0 libs (from /opt/openssl-4.0)
OPENSSL_DIR="/opt/openssl-4.0/lib64"
for lib in libcrypto.so.4 libssl.so.4; do
    if [ -f "$OPENSSL_DIR/$lib" ]; then
        install -m 755 "$OPENSSL_DIR/$lib" "$STAGING/usr/lib/vortex/$lib"
    fi
done

# ld.so config so the runtime linker finds the bundled libs
echo "/usr/lib/vortex" > "$STAGING/etc/ld.so.conf.d/vortex.conf"

# Systemd unit
install -m 644 "$REPO_ROOT/contrib/vortex.service" "$STAGING/lib/systemd/system/vortex.service"

# Example config (don't overwrite an existing config on install)
install -m 644 "$REPO_ROOT/config/vortex.example.yaml" "$STAGING/etc/vortex/vortex.example.yaml"

# ---- 3. DEBIAN control files ----
cat > "$STAGING/DEBIAN/control" <<EOF
Package: vortex
Version: ${VERSION}
Architecture: amd64
Maintainer: Jan Holtzhausen <janholtzhausen@users.noreply.github.com>
Depends: libc6 (>= 2.38), libbpf1, liburing2, libyaml-0-2, libbrotli1, libnghttp2-14
Section: net
Priority: optional
Description: High-performance kernel-assisted reverse proxy
 Vortex is a TLS-terminating reverse proxy using XDP/eBPF for sub-microsecond
 packet filtering, io_uring for async I/O, kTLS for kernel-offloaded TLS
 crypto, and HTTP/3 via QUIC.
EOF

cat > "$STAGING/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
mkdir -p /var/log/vortex /etc/vortex
if [ ! -f /etc/vortex/vortex.yaml ]; then
    cp /etc/vortex/vortex.example.yaml /etc/vortex/vortex.yaml
fi
ldconfig || true
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi
EOF
chmod 755 "$STAGING/DEBIAN/postinst"

# ---- 4. Build .deb ----
OUT="$REPO_ROOT/${PKG}.deb"
dpkg-deb --build --root-owner-group "$STAGING" "$OUT"
echo "==> Built: $OUT  ($(du -sh "$OUT" | cut -f1))"
