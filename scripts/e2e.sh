#!/usr/bin/env bash
# End-to-end test of the `tijori` CLI on a real exFAT volume.
#
# macOS: an hdiutil disk image. Linux: a loop-mounted image (needs sudo and
# exfatprogs). Uses fast, test-only key derivation and no system keychain.
#
# Usage: scripts/e2e.sh [path/to/tijori]
set -euo pipefail

TIJORI=${1:-target/debug/tijori}
TIJORI=$(cd "$(dirname "$TIJORI")" && pwd)/$(basename "$TIJORI")
WORK=$(mktemp -d)
MNT="$WORK/mnt"
PW="orbit lantern cactus velvet mango thunder"
PW2="quartz pelican harbor midnight saffron tundra"
export TIJORI_DATA_DIR="$WORK/data" TIJORI_NO_KEYRING=1 TIJORI_TEST_FAST_KDF=1

mount_image() {
  mkdir -p "$MNT"
  case "$(uname)" in
    Darwin) hdiutil attach -quiet -nobrowse -mountpoint "$MNT" "$WORK/drive.dmg" ;;
    Linux) sudo mount -o "loop,uid=$(id -u),gid=$(id -g)" "$WORK/drive.img" "$MNT" ;;
  esac
}

unmount_image() {
  case "$(uname)" in
    Darwin) hdiutil detach -quiet "$MNT" ;;
    Linux) sudo umount "$MNT" ;;
  esac
}

cleanup() {
  unmount_image 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

case "$(uname)" in
  Darwin) hdiutil create -quiet -size 64m -fs ExFAT -volname TIJORIE2E -o "$WORK/drive.dmg" ;;
  Linux)
    truncate -s 64M "$WORK/drive.img"
    mkfs.exfat -L TIJORIE2E "$WORK/drive.img" >/dev/null
    ;;
  *) echo "unsupported OS" >&2; exit 1 ;;
esac
mount_image

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
t() { echo "$PW" | "$TIJORI" --vault "$MNT" --password-stdin "$@"; }
expect_exit() { # expect_exit CODE STDIN ARGS...
  local want=$1 input=$2; shift 2
  set +e
  echo "$input" | "$TIJORI" --vault "$MNT" --password-stdin "$@" >/dev/null 2>&1
  local got=$?
  set -e
  [ "$got" = "$want" ] || fail "tijori $* exited $got, expected $want"
}

step "source files"
SRC="$WORK/src"
mkdir -p "$SRC/photos/2024" "$SRC/empty-folder"
head -c 3000000 /dev/urandom >"$SRC/photos/2024/big.jpg"
head -c 65536 /dev/urandom >"$SRC/photos/exact-chunk.bin"
: >"$SRC/empty.txt"
printf 'hello from tijori\n' >"$SRC/hello.txt"
printf '#!/bin/sh\necho hi\n' >"$SRC/run.sh"
chmod +x "$SRC/run.sh"
printf 'unicode\n' >"$SRC/café ✓.txt"

step "init"
printf '%s\nI UNDERSTAND\n' "$PW" | "$TIJORI" init "$MNT" --label E2E --password-stdin >"$WORK/init.txt"
grep >/dev/null "If you lose both your password and this recovery phrase" "$WORK/init.txt" || fail "no warning"
PHRASE=$(grep -Eo '[0-9]+\. [a-z]+' "$WORK/init.txt" | awk '{print $2}' | paste -sd' ' -)
[ "$(echo "$PHRASE" | wc -w | tr -d ' ')" = 24 ] || fail "recovery phrase not shown"
[ -f "$MNT/README-TIJORI.txt" ] || fail "no README"
[ -f "$MNT/TIJORI/vault.header" ] && [ -f "$MNT/TIJORI/vault.header.bak" ] || fail "no header"

step "put / ls / get round trip"
t put "$SRC"/* /files
t ls /files
t ls -l /files
OUT="$WORK/out"
mkdir -p "$OUT"
t get /files "$OUT"
diff -r "$SRC" "$OUT/files" || fail "exported tree differs"
[ -x "$OUT/files/run.sh" ] || fail "executable bit lost"
[ "$(t cat /files/hello.txt)" = "hello from tijori" ] || fail "cat"

step "folder commands"
t mkdir -p /archive/old
t mv /files/hello.txt /archive/old
t rm -r /files/photos
t ls /archive/old | grep -x hello.txt >/dev/null || fail "mv"
expect_exit 1 "$PW" rm /archive
t ls /files | grep >/dev/null photos && fail "rm -r"

step "settings, info, keyslots, password"
t settings --label "E2E renamed" --padding off
t info | grep >/dev/null "E2E renamed" || fail "label"
printf '%s\n%s\n' "$PW" "$PW2" | "$TIJORI" --vault "$MNT" --password-stdin keyslot add
t keyslot list | grep -c password | grep -x 2 >/dev/null || fail "keyslot add"
t keyslot remove 2
printf '%s\n%s\n' "$PW" "$PW2" | "$TIJORI" --vault "$MNT" --password-stdin passwd
expect_exit 2 "$PW" ls
PW=$PW2
t ls / >/dev/null
echo "$PHRASE" | "$TIJORI" --vault "$MNT" --password-stdin --with-recovery ls / >/dev/null || fail "recovery unlock"

step "verify / gc"
t verify
t gc

step "shell"
printf '%s\nmkdir /shell\nput %s /shell\nls /shell\nexit\n' "$PW" "$SRC/empty.txt" \
  | "$TIJORI" --vault "$MNT" --password-stdin shell | grep -x empty.txt >/dev/null || fail "shell"

step "unplug and replug"
unmount_image
mount_image
t verify
[ -z "$(find "$MNT/TIJORI" -name '.lock')" ] || fail "lock left behind"

step "re-key"
printf '%s\n%s\nI UNDERSTAND\n' "$PW" "$PW2" | "$TIJORI" --vault "$MNT" --password-stdin rekey >/dev/null
PW=$PW2
t verify
echo "$PHRASE" | "$TIJORI" --vault "$MNT" --password-stdin --with-recovery ls >/dev/null 2>&1 \
  && fail "old recovery phrase still works after re-key"
rm -rf "$OUT" && mkdir -p "$OUT"
t get /archive "$OUT"
[ "$(cat "$OUT/archive/old/hello.txt")" = "hello from tijori" ] || fail "content after re-key"

step "tamper detection"
OBJ=$(find "$MNT/TIJORI/objects" -name '*.tjo' | head -1)
cp "$OBJ" "$WORK/obj.bak"
printf '\xff' | dd of="$OBJ" bs=1 seek=100 conv=notrunc 2>/dev/null
set +e
t verify >/dev/null 2>&1
CODE=$?
set -e
cp "$WORK/obj.bak" "$OBJ"
[ "$CODE" = 0 ] || [ "$CODE" = 3 ] || fail "tampering gave exit $CODE"
t verify >/dev/null

step "backup and restore"
t backup "$WORK/backup"
t backup "$WORK/backup" | grep >/dev/null "nothing new to copy" || fail "second backup copied again"
echo "$PW" | "$TIJORI" --vault "$WORK/backup" --password-stdin verify >/dev/null || fail "backup does not verify"
# Someone deletes the vault from the drive.
rm -rf "$MNT/TIJORI" "$MNT/README-TIJORI.txt" "$MNT/._README-TIJORI.txt"
echo "$PW" | "$TIJORI" --password-stdin restore "$WORK/backup" "$MNT"
t verify >/dev/null
rm -rf "$OUT" && mkdir -p "$OUT"
t get /archive "$OUT"
[ "$(cat "$OUT/archive/old/hello.txt")" = "hello from tijori" ] || fail "content after restore"
[ -z "$(find "$MNT/TIJORI" -name '._*')" ] || fail "AppleDouble files left in the restored vault"

step "timestamps"
case "$(uname)" in
  Darwin) YEAR=$(stat -f %Sm -t %Y "$MNT/TIJORI/vault.header") ;;
  Linux) YEAR=$(date -u -r "$MNT/TIJORI/vault.header" +%Y) ;;
esac
echo "vault.header modified year: $YEAR"
[ "$YEAR" = 2000 ] || [ "$YEAR" = 1999 ] || fail "timestamps not neutralised"

echo
echo "e2e: all checks passed"
