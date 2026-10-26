#!/usr/bin/env bash
# Tests `tijori mount` with real FUSE: macOS (macFUSE 5, FSKit) or Linux
# (fuse3). Uses test-only fast key derivation and no system keychain.
#
# Usage: scripts/mount-test.sh [path/to/tijori] [drive folder]
# Without a drive folder, a temporary folder stands in for the drive.
set -euo pipefail

TIJORI=${1:-target/debug/tijori}
TIJORI=$(cd "$(dirname "$TIJORI")" && pwd)/$(basename "$TIJORI")
WORK=$(mktemp -d)
DRIVE=${2:-$WORK/drive}
mkdir -p "$DRIVE"
PW="orbit lantern cactus velvet mango thunder"
LABEL="TijoriMountTest$$"
export TIJORI_DATA_DIR="$WORK/data" TIJORI_NO_KEYRING=1 TIJORI_TEST_FAST_KDF=1
if [ "$(uname)" = Linux ]; then
  MP_ARG=("$WORK/mnt")
else
  MP_ARG=()
fi

fail() { echo "FAIL: $*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }
t() { echo "$PW" | "$TIJORI" --vault "$DRIVE" --password-stdin "$@"; }

MOUNT_PID=
cleanup() {
  [ -n "$MOUNT_PID" ] && kill -TERM "$MOUNT_PID" 2>/dev/null && wait "$MOUNT_PID" 2>/dev/null || true
  [ -d "$DRIVE/TIJORI.away" ] && mv "$DRIVE/TIJORI.away" "$DRIVE/TIJORI"
  rm -rf "$WORK"
}
trap cleanup EXIT

# Starts `tijori mount` in the background and sets MP to the mount point.
start_mount() {
  : >"$WORK/mount.log"
  # Run tijori itself in the background (not a subshell), so signals reach it.
  echo "$PW" >"$WORK/pw"
  "$TIJORI" --vault "$DRIVE" --password-stdin mount ${MP_ARG[@]+"${MP_ARG[@]}"} --idle-minutes 0 \
    <"$WORK/pw" >>"$WORK/mount.log" 2>&1 &
  MOUNT_PID=$!
  for _ in $(seq 1 100); do
    if grep 'Mounted at' "$WORK/mount.log" >/dev/null 2>&1; then break; fi
    if ! kill -0 "$MOUNT_PID" 2>/dev/null; then cat "$WORK/mount.log"; fail "mount exited"; fi
    sleep 0.2
  done
  MP=$(sed -n 's/^Mounted at \(.*\)\. Press Ctrl+C.*$/\1/p' "$WORK/mount.log" | sed 's/ (read-only)$//')
  [ -d "$MP" ] || { cat "$WORK/mount.log"; fail "no mount point"; }
  echo "mounted at $MP"
}

# Waits for the background mount to end and prints its log.
wait_mount() {
  wait "$MOUNT_PID" || true
  MOUNT_PID=
  cat "$WORK/mount.log"
}

step "create a vault"
printf '%s\nI UNDERSTAND\n' "$PW" | "$TIJORI" init "$DRIVE" --label "$LABEL" --password-stdin >/dev/null

step "mount and use it with ordinary tools"
start_mount
SRC="$WORK/src"
mkdir -p "$SRC"
head -c 3000000 /dev/urandom >"$SRC/big.bin"
echo "hello" >"$MP/hello.txt"
echo "more" >>"$MP/hello.txt"
[ "$(cat "$MP/hello.txt")" = "$(printf 'hello\nmore')" ] || fail "append"
mkdir "$MP/docs"
cp "$SRC/big.bin" "$MP/docs/"
cmp "$SRC/big.bin" "$MP/docs/big.bin" || fail "big file"
mv "$MP/hello.txt" "$MP/docs/greeting.txt"
mkdir "$MP/tmp" && echo x >"$MP/tmp/x" && rm -r "$MP/tmp"
ls -la "$MP" "$MP/docs"
if touch "$MP/._junk" 2>/dev/null; then fail "AppleDouble file was accepted"; fi
if echo x >"$MP/.DS_Store" 2>/dev/null; then fail ".DS_Store was accepted"; fi
df -h "$MP" | tail -1
PERMS=$(ls -ld "$MP/docs" | cut -c1-10)
[ "$PERMS" = drwx------ ] || fail "folder permissions are $PERMS, not owner-only"

step "unmount on a termination signal (as at logout); changes are committed"
kill -TERM "$MOUNT_PID"
wait_mount
grep 'Unmounted on request' "$WORK/mount.log" >/dev/null || fail "not unmounted on request"
[ -z "$(find "$DRIVE/TIJORI" -name .lock)" ] || fail "lock left behind"
t verify
[ "$(t cat /docs/greeting.txt)" = "$(printf 'hello\nmore')" ] || fail "content after unmount"
t get /docs/big.bin "$WORK" >/dev/null
cmp "$SRC/big.bin" "$WORK/big.bin" || fail "big file after unmount"

step "eject from outside"
start_mount
echo "eject test" >"$MP/eject.txt"
sleep 3 # let the coalesced commit run
case "$(uname)" in
  Darwin) diskutil unmount "$MP" >/dev/null ;;
  Linux) fusermount3 -u "$MP" ;;
esac
wait_mount
grep 'because the volume was ejected' "$WORK/mount.log" >/dev/null || fail "eject not noticed"
[ "$(t cat /eject.txt)" = "eject test" ] || fail "content after eject"

step "drive removed while mounted"
start_mount
echo "before removal" >"$MP/removal.txt"
sleep 3
mv "$DRIVE/TIJORI" "$DRIVE/TIJORI.away"
wait_mount
grep 'because the drive was removed' "$WORK/mount.log" >/dev/null || fail "removal not noticed"
mv "$DRIVE/TIJORI.away" "$DRIVE/TIJORI"
# A crashed session may leave its lock; reading needs no lock.
t verify
t ls /

echo
echo "mount test: all checks passed"
