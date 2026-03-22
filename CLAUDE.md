# Vortex — Claude Code Instructions

## Git identity

All commits in this repo MUST be authored as **janholtzhausen** only.
The local git config already enforces this:

```
user.name  = janholtzhausen
user.email = 85851215+janholtzhausen@users.noreply.github.com
```

**Never** add `Co-Authored-By` trailers to commit messages — GitHub treats
them as contributors and adds unwanted entries to the contributors list.

## Deployment

- Deploy via `.deb` only: `bash tools/build_deb.sh [version]`
- Copy as `debian@10.76.8.2` (NOT root, NOT netwatch.tv)
- `sudo dpkg -i /tmp/vortex_*.deb && sudo systemctl restart vortex`

## Testing

After any functional change, run Playwright browser tests:

```
cd /home/janh/dev/vortex-ui-test && npx playwright test --reporter=line
```

All 6 tests must pass before pushing.

## Known constraints

- kTLS TX is incompatible with splice and send_zc on kernel 6.8 — do not re-enable
- XDP/tarpit blocklist is IPv4-only regardless of `ipv4_only` setting
- TLS handshakes are offloaded to `tls_pool` (4 threads) — do not block the io_uring loop with SSL_accept
