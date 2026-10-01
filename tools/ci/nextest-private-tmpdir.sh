#!/bin/sh
# nextest wrapper script (.config/nextest.toml): runs one test process with a private TMPDIR,
# removes it afterwards, and fails a test that exited 0 but left anything in it.
#
# Every test and every process it starts inherits the private TMPDIR, so whatever a test forgets
# (a scratch directory, a daemon's locator file, a socket) is removed here even when the test
# panics, and a passing test that leaks is reported by name instead of filling the shared temp
# directory (767,725 entries on 2026-10-01). A wrapper killed outright (SIGKILL) cannot clean up;
# its directory is named after its pid and the next wrapper whose pid check finds it dead
# removes it.
set -u

# A test that runs nextest itself (crates/fireemu/tests/leak_fixture.rs) passes the root on, so
# the nested wrapper's directories are siblings and nothing is created inside the outer test's.
parent=${TMPDIR:-/tmp}
parent=${parent%/}
root=${FIREEMU_TEST_TMP_ROOT:-$parent/fireemu-test-tmp}
mkdir -p "$root" || exit 70

for stale in "$root"/*; do
    [ -L "$stale" ] && continue
    [ -d "$stale" ] && [ -O "$stale" ] || continue
    name=${stale##*/}
    pid=${name%%.*}
    case $pid in '' | *[!0-9]*) continue ;; esac
    [ "$name" = "$pid.${name#*.}" ] || continue
    kill -0 "$pid" 2>/dev/null && continue
    chmod -R u+rwx "$stale" 2>/dev/null
    rm -rf "$stale"
done

dir=$(mktemp -d "$root/$$.XXXXXX") || exit 70

# A terminating signal reaches the test too (nextest signals the process group); the wrapper
# waits for the test to exit and then cleans up.
signal=0
trap 'signal=129' HUP
trap 'signal=130' INT
trap 'signal=143' TERM

TMPDIR=$dir/ FIREEMU_TEST_TMP_ROOT=$root "$@"
status=$?

left=$(ls -A "$dir")
chmod -R u+rwx "$dir" 2>/dev/null
rm -rf "$dir"

if [ -n "$left" ]; then
    printf 'nextest-private-tmpdir: the test left these entries in TMPDIR (removed now):\n%s\n' "$left" >&2
    if [ "$status" -eq 0 ] && [ "$signal" -eq 0 ]; then
        status=1
    fi
fi
if [ "$status" -eq 0 ] && [ "$signal" -ne 0 ]; then
    status=$signal
fi
exit "$status"
