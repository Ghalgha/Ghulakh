#!/usr/bin/env python3
"""Failure-path tests for secure device credential digest file handling."""
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile


TOOL = pathlib.Path(__file__).with_name("create_credential.py")


def invoke(path: pathlib.Path, directory: pathlib.Path, mode: str = "0640", gid: int | None = None):
    command = [
        sys.executable, str(TOOL), "--digest-file", str(path),
        "--mode", mode, "--expected-uid", str(os.geteuid()),
        "--expected-gid", str(os.getegid() if gid is None else gid),
    ]
    return subprocess.run(command, text=True, capture_output=True, check=False)


def expect_refused(path: pathlib.Path, directory: pathlib.Path, **kwargs):
    before = None
    if path.exists() and path.is_file() and not path.is_symlink():
        before = path.read_bytes()
    result = invoke(path, directory, **kwargs)
    assert result.returncode != 0, (path, result.stdout, result.stderr)
    assert result.stdout == "", "refused credential must never be printed"
    if before is not None:
        assert path.read_bytes() == before, "refused operation modified digest file"


def main():
    with tempfile.TemporaryDirectory(prefix="ghulakh-credential-test-") as raw:
        root = pathlib.Path(raw)
        regular = root / "digests"
        regular.write_text("", encoding="ascii")
        regular.chmod(0o640)
        success = invoke(regular, root)
        assert success.returncode == 0, success.stderr
        secret = success.stdout.strip()
        assert len(secret) == 64
        lines = regular.read_text(encoding="ascii").splitlines()
        assert lines == [hashlib.sha256(secret.encode("ascii")).hexdigest()]
        assert secret not in regular.read_text(encoding="ascii")

        full_device = pathlib.Path("/dev/full")
        if full_device.exists():
            before_delivery_failure = regular.read_bytes()
            command = [
                sys.executable, str(TOOL), "--digest-file", str(regular),
                "--mode", "0640", "--expected-uid", str(os.geteuid()),
                "--expected-gid", str(os.getegid()),
            ]
            with full_device.open("wb") as sink:
                failed_delivery = subprocess.run(command, stdout=sink, stderr=subprocess.PIPE, check=False)
            assert failed_delivery.returncode != 0
            assert regular.read_bytes() == before_delivery_failure, "failed secret delivery left an unusable digest"

        target = root / "target"
        target.write_text("untouched\n", encoding="ascii")
        target.chmod(0o640)
        symlink = root / "symlink"
        symlink.symlink_to(target)
        expect_refused(symlink, root)
        assert target.read_text(encoding="ascii") == "untouched\n"

        wrong_mode = root / "wrong-mode"
        wrong_mode.write_text("original\n", encoding="ascii")
        wrong_mode.chmod(0o600)
        expect_refused(wrong_mode, root)

        linked = root / "hardlinked"
        linked.write_text("original\n", encoding="ascii")
        linked.chmod(0o640)
        os.link(linked, root / "hardlink-alias")
        expect_refused(linked, root)

        fifo = root / "fifo"
        os.mkfifo(fifo, 0o640)
        expect_refused(fifo, root)

        wrong_gid = root / "wrong-gid"
        wrong_gid.write_text("original\n", encoding="ascii")
        wrong_gid.chmod(0o640)
        expect_refused(wrong_gid, root, gid=os.getegid() + 1)

        parent_target = root / "real-parent"
        parent_target.mkdir()
        parent_file = parent_target / "digests"
        parent_file.write_text("original\n", encoding="ascii")
        parent_file.chmod(0o640)
        parent_link = root / "linked-parent"
        parent_link.symlink_to(parent_target, target_is_directory=True)
        expect_refused(parent_link / "digests", root)

    print("Credential digest path safety tests passed.")


if __name__ == "__main__":
    main()
