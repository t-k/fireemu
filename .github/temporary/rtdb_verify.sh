#!/usr/bin/env bash
set -euo pipefail
out=/tmp/rtdb-verify
cgroup=$(awk -F: '$1 == "0" {print $3}' /proc/self/cgroup)
cat "/sys/fs/cgroup$cgroup/memory.max" "/sys/fs/cgroup$cgroup/memory.swap.max" > "$out/cgroup.txt"
test "$(cat "/sys/fs/cgroup$cgroup/memory.max")" = 6442450944
test "$(cat "/sys/fs/cgroup$cgroup/memory.swap.max")" = 0
cargo fmt --all -- --check > "$out/fmt.log" 2>&1
cargo nextest run -p fireemu-core-database -p fireemu-adapter-database --profile pr --locked --no-fail-fast -j 2 > "$out/nextest.log" 2>&1
cargo clippy -p fireemu-core-database -p fireemu-adapter-database --all-targets --all-features --locked -j 2 -- -D warnings > "$out/clippy.log" 2>&1
cargo build -p fireemu --locked -j 2 > "$out/build.log" 2>&1
sha256sum target/debug/fireemu > "$out/binary.sha256"
cargo test -p fireemu-core-database --test rules auth_root_identity_matches_the_recorded_read --locked -j 2 > "$out/noop.log" 2>&1
cp crates/fireemu-core-database/src/rules/eval.rs "$out/eval-original.rs"
python3 - <<'PY'
p='crates/fireemu-core-database/src/rules/eval.rs'
s=open(p).read(); old='(Value::Auth(_), Value::Auth(_)) => true,'; assert s.count(old)==1; open(p,'w').write(s.replace(old,'(Value::Auth(_), Value::Auth(_)) => false,'))
PY
set +e
cargo test -p fireemu-core-database --test rules auth_root_identity_matches_the_recorded_read --locked -j 2 > "$out/mutant.log" 2>&1
status=$?
set -e
cp "$out/eval-original.rs" crates/fireemu-core-database/src/rules/eval.rs
printf '%s\n' "$status" > "$out/mutant-status.txt"
test "$status" = 101
grep -F 'assertion failed: rules.can_read' "$out/mutant.log"
git diff --exit-code
