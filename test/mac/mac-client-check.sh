#!/bin/bash
# Checks portable-smb-server from macOS's own SMB client (mount_smbfs), the one client the Go e2e
# tests cannot stand in for: the native client negotiates Apple's SMB2 extensions and, without them,
# enumerates a directory by looking every entry up one at a time.
#
# Run it ON a Mac, against a server reachable from it:
#   test/mac/mac-client-check.sh HOST PORT SHARE USER PASSWORD [DIR-WITH-MANY-FILES]
#
# The share needs a folder with thousands of files (default name "many"; make one with
# `mkdir many && seq -w 1 5000 | xargs -I{} touch many/f{}`), and a file called medium.bin or
# any file in the share root is used for the read check. Exits 1 on any FAIL. Every step is timed;
# a listing of the big folder that takes more than a few seconds over a LAN means the Apple
# extensions are not in play.
set -u
host=${1:?host}; port=${2:?port}; share=${3:?share}; user=${4:?user}; pass=${5:?password}; many=${6:-many}
mp=$(mktemp -d /tmp/psmb-mac.XXXXXX)
failed=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; failed=1; }
now() { perl -MTime::HiRes=time -e 'print time'; }
elapsed() { perl -e "printf('%.1f', $(now) - $1)"; }

if mount -t smbfs "//${user}:${pass}@${host}:${port}/${share}" "$mp" 2>/dev/null; then
  pass "mounted //${host}:${port}/${share}"
else
  fail "mount_smbfs //${host}:${port}/${share}"; rmdir "$mp"; exit 1
fi
trap 'umount "$mp" 2>/dev/null || diskutil unmount force "$mp" >/dev/null 2>&1; rmdir "$mp" 2>/dev/null' EXIT

# Apple extensions in play? smbutil statshares shows the negotiated capabilities.
if smbutil statshares -m "$mp" 2>/dev/null | grep -qi 'aapl\|APPLE'; then
  pass "Apple SMB extensions negotiated (smbutil statshares)"
else
  echo "INFO  smbutil statshares does not name the Apple extensions; the timings below tell"
fi

t=$(now); n=$(ls -A1 "$mp" | wc -l | tr -d ' '); pass "root lists $n entries in $(elapsed $t) s"

if [ -d "$mp/$many" ]; then
  t=$(now); n=$(ls -f "$mp/$many" | wc -l | tr -d ' '); d=$(elapsed $t)
  if [ "$n" -gt 1000 ] && perl -e "exit(($d < 30) ? 0 : 1)"; then pass "$many lists $n names in $d s (ls -f)"; else fail "$many: $n names in $d s (ls -f)"; fi
  t=$(now); n=$(ls -l "$mp/$many" | wc -l | tr -d ' '); d=$(elapsed $t)
  if perl -e "exit(($d < 60) ? 0 : 1)"; then pass "$many lists with attributes in $d s (ls -l)"; else fail "$many: ls -l took $d s"; fi
else
  fail "no folder named $many in the share"
fi

# a read: whichever regular file in the root is first
f=$(find "$mp" -maxdepth 1 -type f | head -1)
if [ -n "$f" ]; then
  t=$(now); h1=$(shasum -a 256 "$f" | cut -d' ' -f1); d=$(elapsed $t)
  size=$(stat -f %z "$f")
  pass "read $(basename "$f") ($size bytes) in $d s, sha256 $h1"
else
  fail "no file in the share root to read"
fi

# a write round trip (skipped on a read-only share)
w="$mp/.mac-check-$$"
if mkdir "$w" 2>/dev/null; then
  if printf hello > "$w/a.txt" && mv "$w/a.txt" "$w/b.txt" && [ "$(cat "$w/b.txt")" = hello ] && rm "$w/b.txt" && rmdir "$w"; then
    pass "write round trip (create, write, rename, read back, delete)"
  else
    fail "write round trip"; rm -rf "$w" 2>/dev/null
  fi
else
  echo "INFO  share is read-only, no write round trip"
fi

exit $failed
