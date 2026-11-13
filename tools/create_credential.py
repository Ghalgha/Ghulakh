#!/usr/bin/env python3
"""Create a 256-bit device credential and append only its SHA-256 digest.

The digest file must already exist as a single-link regular file with the
expected owner, group and mode. Symlinks and non-regular files are rejected.
"""
import argparse
import fcntl
import hashlib
import os
import secrets
import stat
import sys
from pathlib import Path


def open_verified_digest(path: Path, expected_uid: int, expected_gid: int, mode: int) -> int:
    parent = path.parent
    name = path.name
    if not name or name in (".", ".."):
        raise ValueError("invalid digest filename")

    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    dir_fd = os.open(parent, dir_flags)
    try:
        dir_stat = os.fstat(dir_fd)
        if not stat.S_ISDIR(dir_stat.st_mode) or dir_stat.st_uid != expected_uid:
            raise ValueError("digest parent owner does not match expected owner")

        flags = os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = os.open(name, flags, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)

    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("digest path is not a regular file")
        if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (expected_uid, expected_gid, mode):
            raise ValueError("digest file owner, group or mode does not match policy")
        if info.st_nlink != 1:
            raise ValueError("digest file must have exactly one hard link")
        return fd
    except BaseException:
        os.close(fd)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--digest-file", required=True, type=Path)
    parser.add_argument("--mode", choices=("0600", "0640"), default="0600")
    parser.add_argument("--expected-uid", type=int, default=0)
    parser.add_argument("--expected-gid", type=int, default=0)
    args = parser.parse_args()
    mode = int(args.mode, 8)

    try:
        fd = open_verified_digest(args.digest_file, args.expected_uid, args.expected_gid, mode)
        with os.fdopen(fd, "a", encoding="ascii", closefd=True) as digest_file:
            fcntl.flock(digest_file.fileno(), fcntl.LOCK_EX)
            original_size = os.fstat(digest_file.fileno()).st_size
            credential = secrets.token_hex(32)
            digest = hashlib.sha256(credential.encode("ascii")).hexdigest() + "\\n"
            try:
                digest_file.write(digest)
                digest_file.flush()
                os.fsync(digest_file.fileno())
            except BaseException:
                os.ftruncate(digest_file.fileno(), original_size)
                os.fsync(digest_file.fileno())
                raise
    except (OSError, ValueError) as error:
        sys.stderr.write(f"Credential creation refused: {error}\\n")
        return 1

    sys.stdout.write(credential + "\\n")
    sys.stderr.write("Credential created. Store the displayed secret securely; the server file contains only its SHA-256 digest.\\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
