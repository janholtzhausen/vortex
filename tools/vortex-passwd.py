#!/usr/bin/env python3
import argparse
import base64
import getpass
import hashlib
import secrets
import sys


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a Vortex Basic-auth scrypt verifier."
    )
    parser.add_argument("username")
    parser.add_argument("--log-n", type=int, default=15)
    parser.add_argument("--r", type=int, default=8)
    parser.add_argument("--p", type=int, default=1)
    parser.add_argument("--salt-bytes", type=int, default=16)
    parser.add_argument("--hash-bytes", type=int, default=32)
    parser.add_argument("--maxmem", type=int, default=64 * 1024 * 1024)
    args = parser.parse_args()

    if ":" in args.username or not args.username:
        print("username must be non-empty and must not contain ':'", file=sys.stderr)
        return 1
    if args.log_n < 1 or args.log_n > 20:
        print("--log-n must be between 1 and 20", file=sys.stderr)
        return 1
    if args.r <= 0 or args.p <= 0:
        print("--r and --p must be positive", file=sys.stderr)
        return 1

    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm: ")
    if password != confirm:
        print("passwords do not match", file=sys.stderr)
        return 1

    salt = secrets.token_bytes(args.salt_bytes)
    n = 1 << args.log_n
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=args.r,
        p=args.p,
        dklen=args.hash_bytes,
        maxmem=args.maxmem,
    )
    print(
        f'{args.username}:$scrypt$ln={args.log_n},r={args.r},p={args.p}$'
        f"{b64(salt)}${b64(digest)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
