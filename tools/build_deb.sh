#!/bin/bash
# Build a .deb package for vortex.
# Usage: tools/build_deb.sh [version]
# Default version is derived from git describe (e.g. 0.2.1).
# Output: vortex_<version>_amd64.deb in the repo root.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build-release"
VERSION="${1:-$(git -C "$REPO_ROOT" describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "0.1.0")}"
PKG="vortex_${VERSION}_amd64"
STAGING="/tmp/${PKG}"

echo "==> Building vortex .deb  version=${VERSION}"

# ---- 1. Compile ----
cmake -S "$REPO_ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DFORCE_OPENSSL_BUNDLED=ON -Wno-dev -DCMAKE_EXPORT_COMPILE_COMMANDS=OFF 2>/dev/null
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
Depends: libc6 (>= 2.38), libbpf1, liburing2, libyaml-0-2
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
