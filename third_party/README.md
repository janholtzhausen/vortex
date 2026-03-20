# Third-party dependencies

## OpenSSL 4.0

OpenSSL 4.0 is not yet in distro packages (targets April 2026 release).
Build from source:

```bash
git clone https://github.com/openssl/openssl.git
cd openssl
git checkout openssl-4.0.0-alpha1   # or latest tag: git tag -l 'openssl-4*' | tail -5

./Configure \
    --prefix=/opt/openssl-4.0 \
    --openssldir=/opt/openssl-4.0/ssl \
    enable-ktls \
    enable-tls1_3 \
    enable-ec_nistp_64_gcc_128 \
    no-ssl3 no-tls1 no-tls1_1 \
    -DOPENSSL_LINUX_TLS

make -j$(nproc)
sudo make install
```

Then build vortex with:
```bash
cmake -DOPENSSL_ROOT_DIR=/opt/openssl-4.0 ..
```

**CRITICAL**: OpenSSL 4.0 removes ENGINE API. Use OSSL_PROVIDER framework only.
Never include `<openssl/engine.h>`.
