# Dashboard / State Notes

## Current state
- Dashboard implementation exists and is wired into the build and runtime.
- Config support for `dashboard.enabled`, `dashboard.bind_address`, and `dashboard.port` is in place.
- `src/dashboard.c` is built and the dashboard can be served on `http://127.0.0.1:9091/`.
- Version `0.6.25` was built, deployed, and installed on `debian@10.76.8.2`.

## Completed in 0.6.25
- Added configurable buffered request-body limits for HTTP/2 and HTTP/3/QUIC:
  - `global.max_request_body_mb`
  - `global.max_request_body_bytes`
- Enforced those limits in the H2 and H3 request buffering paths.
- Added TLS handshake-pool metrics:
  - queue depth
  - active handshakes
  - submitted / completed / failed / dropped totals
- Fixed the injected HSTS header length bug that caused `ERR_HTTP2_PROTOCOL_ERROR` on the `*.netwatch.tv` browser checks.

## Verification state
- The required browser-level `netwatch-browser.spec.js` checks passed after deployment.
- Authenticated HTTP/2 curl to `https://nzbget.netwatch.tv/` is clean after deployment.

## Remaining known issues
- The broader Playwright suite still has 7 failures outside the required browser gate:
  - 6 `netwatch-equivalence` failures
  - 1 `sonarr-console` failure
- The observed failures are in two buckets:
  - equivalence tests hitting intermittent `ERR_CONNECTION_REFUSED` / content mismatches
  - Sonarr WebSocket/auth handling producing console errors
- Local C test targets are still misconfigured:
  - `ctest` discovers no tests from the default build
  - explicit test targets fail because their include paths still reference `../src/*.h` while headers live under `include/`

## Next useful follow-ups
- Fix the test CMake/include-path setup so `test_config`, `test_log`, and `test_cache` build and run normally.
- Investigate the remaining equivalence failures separately from the request-limit/TLS-pool work.
- Investigate Sonarr WebSocket/auth handling behind the proxy.
