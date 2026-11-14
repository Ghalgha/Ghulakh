#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY="$ROOT/tools/deploy-server.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
sed -n '/^verify_release_tree() {/,/^}/p' "$DEPLOY" >"$TMP/ownership-function.sh"
source "$TMP/ownership-function.sh"

RELEASES="$TMP/releases"
mkdir -p "$RELEASES/release"
chmod 0755 "$RELEASES" "$RELEASES/release"
chown root:root "$RELEASES" "$RELEASES/release"
: >"$TMP/mountinfo"
verify_release_tree "$RELEASES" "$TMP/mountinfo"

mkdir "$RELEASES/release/mounted"
printf '10 1 0:2 / %s/release/mounted rw - tmpfs tmpfs rw\n' "$RELEASES" >"$TMP/mountinfo"
if verify_release_tree "$RELEASES" "$TMP/mountinfo"; then
  echo "Nested mount point was accepted in release tree." >&2
  exit 1
fi
: >"$TMP/mountinfo"

ln -s release "$RELEASES/symlink"
if verify_release_tree "$RELEASES" "$TMP/mountinfo"; then
  echo "Symbolic link was accepted in release tree." >&2
  exit 1
fi
rm "$RELEASES/symlink"

printf 'linked inode\n' >"$RELEASES/release/file-a"
ln "$RELEASES/release/file-a" "$RELEASES/release/file-b"
if verify_release_tree "$RELEASES" "$TMP/mountinfo"; then
  echo "Hard-linked file was accepted in release tree." >&2
  exit 1
fi
rm "$RELEASES/release/file-a" "$RELEASES/release/file-b"

printf 'foreign owner\n' >"$RELEASES/release/foreign"
chown 65534:65534 "$RELEASES/release/foreign"
if verify_release_tree "$RELEASES" "$TMP/mountinfo"; then
  echo "Non-root-owned file was accepted in release tree." >&2
  exit 1
fi

echo "Release ownership regression tests passed."
