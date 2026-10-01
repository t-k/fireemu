#!/bin/sh
# nextest wrapper script (.config/nextest.toml): runs one test process with a private TMPDIR,
# removes it afterwards, and fails a test that exited 0 but left anything in it.
#
# Every test and every process it starts inherits the private TMPDIR, so whatever a test forgets
# (a scratch directory, a daemon's locator file, a socket) is removed here even when the test
# panics, and a passing test that leaks is reported by name instead of filling the shared temp
# directory (767,725 entries on 2026-10-01).
#
# The private directories live under one root per user, `fireemu-test-tmp-<uid>` in TMPDIR (or
# /tmp). The root must be a real directory owned by the user with mode 0700; anything else (a
# symbolic link, another user's directory, one others can write) is refused, because the wrapper
# deletes directories under it. A wrapper killed outright (SIGKILL) cannot clean up; its
# directory `run-<pid>.XXXXXX` is removed by the next wrapper that finds that pid gone.
#
# Not covered: a process the test started and left running can write into the directory after
# it is removed (nextest's leak detection reports such processes when they keep the test's
# output open). Cleanup waits for the test process only.
set -u

refuse() {
    printf 'nextest-private-tmpdir: refusing to run: %s\n' "$1" >&2
    exit 70
}

# A test that runs nextest itself (crates/fireemu/tests/leak_fixture.rs) passes the root on, so
# the nested wrapper's directories are siblings and nothing is created inside the outer test's.
parent=${TMPDIR:-/tmp}
parent=${parent%/}
root=${FIREEMU_TEST_TMP_ROOT:-$parent/fireemu-test-tmp-$(id -u)}
(umask 077 && mkdir -p "$root") 2>/dev/null || refuse "cannot create $root"
[ -L "$root" ] && refuse "$root is a symbolic link"
[ -d "$root" ] || refuse "$root is not a directory"
# shellcheck disable=SC3067 # test -O is in dash, bash and busybox; without it the root is refused.
[ -O "$root" ] || refuse "$root is not owned by this user"
case $(ls -ld "$root") in
drwx------*) ;;
*) refuse "$root must have mode 0700" ;;
esac

for stale in "$root"/run-*; do
    [ -L "$stale" ] && continue
    # shellcheck disable=SC3067
    [ -d "$stale" ] && [ -O "$stale" ] || continue
    name=${stale##*/}
    case $name in
    run-*.[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]) ;;
    *) continue ;;
    esac
    pid=${name#run-}
    pid=${pid%.*}
    case $pid in '' | *[!0-9]*) continue ;; esac
    kill -0 "$pid" 2>/dev/null && continue
    chmod -R u+rwx "$stale" 2>/dev/null
    rm -rf "$stale"
done

dir=$(mktemp -d "$root/run-$$.XXXXXX") || refuse "cannot create a directory in $root"

# A terminating signal reaches the test too (nextest signals the process group); the wrapper
# waits for the test to exit and then cleans up.
signal=0
trap 'signal=129' HUP
trap 'signal=130' INT
trap 'signal=143' TERM

TMPDIR=$dir/ FIREEMU_TEST_TMP_ROOT=$root "$@"
status=$?

# Make everything readable first, so a test cannot hide a leftover by removing permissions.
chmod -R u+rwx "$dir" 2>/dev/null
if ! left=$(ls -A "$dir" 2>&1); then
    left="(the directory could not be listed: $left)"
fi
rm -rf "$dir"
if [ -e "$dir" ]; then
    left="$left
(the directory could not be removed: $dir)"
fi

if [ -n "$left" ]; then
    printf 'nextest-private-tmpdir: the test left these entries in TMPDIR (removed now):\n%s\n' "$left" >&2
    if [ "$status" -eq 0 ] && [ "$signal" -eq 0 ]; then
        status=1
    fi
fi
if [ "$status" -eq 0 ] && [ "$signal" -ne 0 ]; then
    status=$signal
fi

# A test killed by a signal (or interrupted) is reported the same way, so nextest shows the
# signal (SIGABRT, SIGSEGV, ...) rather than an exit code 128+n.
if [ "$status" -gt 128 ] && [ "$status" -lt 160 ]; then
    name=$(kill -l "$((status - 128))" 2>/dev/null)
    case ${name#SIG} in
    HUP | INT | QUIT | ILL | TRAP | ABRT | BUS | FPE | KILL | SEGV | SYS | PIPE | ALRM | TERM | USR1 | USR2 | XCPU | XFSZ | VTALRM | PROF)
        trap - HUP INT TERM
        kill -s "${name#SIG}" "$$"
        ;;
    esac
fi
exit "$status"
