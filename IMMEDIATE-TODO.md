# Immediate TODO

No blocking issues as of v1.0.13.

## Current state

- All 5 unit tests pass (`ctest --test-dir build`)
- clang-format enforced across all sources (`.clang-format` in root)
- Gauntlet quality gates: build, format, cppcheck, clang-tidy, semgrep, gitleaks, trivy — all pass
- Service running at `debian@10.76.8.2`, v1.0.13

## Known remaining clang-tidy noise (non-blocking)

- `src/auth.c` — `bugprone-implicit-widening-of-multiplication-result` on uint32_t
  arithmetic in scrypt BlockMix/ROMix. Malloc overflow risk already fixed with `(size_t)` casts;
  remaining hits are pointer-arithmetic widens that are safe for normal scrypt parameters (r ≤ 8).
- `src/conn.c` — `bugprone-multi-level-implicit-pointer-conversion` on `calloc → uint8_t **`.
  Valid C; clang-tidy being pedantic about `void *` multi-level promotion.
- `src/config.c` — `bugprone-branch-clone` in YAML state machine. Intentional fall-through
  shared handler paths.
- `cert/acme_client.c` — `clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling`
  on memcpy/memset. `_s`-variants (Annex K) are not available on Linux glibc; false positive.
