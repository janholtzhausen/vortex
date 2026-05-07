# Vortex — Claude Code Instructions

## Git identity

All commits in this repo MUST be authored as **janholtzhausen** only.
The local git config already enforces this:

```sh
user.name  = janholtzhausen
user.email = 85851215+janholtzhausen@users.noreply.github.com
```

**Never** add `Co-Authored-By` trailers to commit messages — GitHub treats
them as contributors and adds unwanted entries to the contributors list.

GitHub must show **janholtzhausen** as the only contributor for this repo.
Do not use any author/committer identity other than:

```sh
janholtzhausen <85851215+janholtzhausen@users.noreply.github.com>
```

## Deployment

- Deploy via `.deb` only: `bash tools/build_deb.sh [version]`
- Copy as `debian@10.76.8.2` (NOT root, NOT netwatch.tv)
- `sudo dpkg -i /tmp/vortex_*.deb && sudo systemctl restart vortex`

## Testing

After any functional change, run Playwright browser tests:

```sh
cd /home/janh/dev/vortex-ui-test && npx playwright test --reporter=line
```

All 6 tests must pass before pushing.

- Always do browser-level tests for the `*.netwatch.tv` targets. The targets can be found in the Vortex config.
- Always use browser-level HTTP auth for the `*.netwatch.tv` targets. Do not rely on header-only auth for browser tests; use the browser's auth mechanism.
- Always test all configured `*.netwatch.tv` targets from the active Vortex config, not just a subset.
- Never spend more than 1 minute testing a single target.
- Always stop the test immediately when the first error is found. Fail fast, fix fast.

## Known constraints

- kTLS TX is incompatible with splice on kernel 6.8 — begin_splice is gated on `!CONN_FLAG_KTLS_TX`; do not remove this check
- send_zc is similarly gated on `!CONN_FLAG_KTLS_TX` — do not remove
- XDP/tarpit blocklist is IPv4-only regardless of `ipv4_only` setting
- TLS handshakes are offloaded to `tls_pool` (4 threads) — do not block the io_uring loop with SSL_accept
