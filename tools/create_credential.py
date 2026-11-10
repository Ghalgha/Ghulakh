#!/usr/bin/env python3
"""Create a 256-bit device credential and append only its SHA-256 digest."""

import argparse
import hashlib
import os
import secrets
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--digest-file",
        required=True,
        type=Path,
        help="server-side file to which the credential digest is appended",
    )
    args = parser.parse_args()

    credential = secrets.token_hex(32)
    digest = hashlib.sha256(credential.encode("ascii")).hexdigest()
    path = args.digest_file
    path.parent.mkdir(parents=True, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, (digest + "\n").encode("ascii"))
    finally:
        os.close(descriptor)

    os.chmod(path, 0o600)
    sys.stdout.write(credential + "\n")
    sys.stderr.write(
        "Credential created. Store the displayed secret securely; "
        "the server file contains only its SHA-256 digest.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
