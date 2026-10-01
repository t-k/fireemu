import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { rehearse, standinSha256 } from "./storage-object-compare/rehearse.mjs";
import { rehearseCommand } from "./storage-object-compare/run.mjs";
import { tempDir } from "./test-tmpdir.mjs";

const sha256 = (text) => createHash("sha256").update(text).digest("hex");
const COMMIT = "b0fc2485d5596439b515f4fd12f6c3ce68d4af91";
// A throwaway repository: the global git configuration (signing, hooks) is not this test's business.
const gitEnv = {
  ...process.env,
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_AUTHOR_NAME: "t",
  GIT_AUTHOR_EMAIL: "t@example.com",
  GIT_COMMITTER_NAME: "t",
  GIT_COMMITTER_EMAIL: "t@example.com",
};
const git = (cwd, ...args) => spawnSync("git", args, { cwd, env: gitEnv, encoding: "utf8" });

function setup({ clean = true, script } = {}) {
  const root = tempDir("compare-rehearse-");
  const recorder = join(root, "recorder");
  mkdirSync(join(recorder, "conformance"), { recursive: true });
  writeFileSync(join(recorder, "conformance", "file.txt"), "x");
  git(recorder, "init", "-q");
  git(recorder, "add", ".");
  git(recorder, "commit", "-q", "-m", "x");
  if (!clean) writeFileSync(join(recorder, "conformance", "dirty.txt"), "y");
  const events = join(root, "events");
  mkdirSync(events);
  writeFileSync(join(events, "aggregate-events.jsonl"), '{"type":"recipe-begin"}\n');
  const binary = join(root, "fireemu");
  writeFileSync(
    binary,
    script ??
      `#!/bin/sh
if [ "$1" = "--version" ]; then echo "fireemu 9.9.9"; exit 0; fi
echo '{"status":"LOCAL_COMPLETE","completedRecipes":[26,0],"requests":2446,"eventDirectory":"${events}"}'
`,
  );
  chmodSync(binary, 0o755);
  const rules = join(root, "rules.rules");
  writeFileSync(rules, "rules");
  const fixture = join(root, "fx");
  mkdirSync(fixture);
  writeFileSync(join(fixture, "index.json"), '{"recipes":[]}');
  return { root, recorder, binary, rules, fixture, out: join(root, "out"), events };
}
const input = (s, over = {}) => ({
  fireemuBinary: s.binary,
  fireemuCommit: COMMIT,
  recorderDir: s.recorder,
  rulesFile: s.rules,
  fixtureDir: s.fixture,
  outDir: s.out,
  sandbox: false,
  timeoutMs: 20_000,
  ...over,
});

test("the rehearsal runs the binary, copies the journal and writes a receipt that binds the binary, the commits and the journal", async () => {
  const s = setup();
  const receipt = await rehearse(input(s));
  const journal = join(s.out, "journal.jsonl");
  assert.equal(readFileSync(journal, "utf8"), '{"type":"recipe-begin"}\n');
  assert.equal(receipt.fireemu.binarySha256, sha256(readFileSync(s.binary)));
  assert.equal(receipt.fireemu.version, "fireemu 9.9.9");
  assert.equal(receipt.fireemu.commit, COMMIT);
  assert.equal(receipt.recorder.commit, git(s.recorder, "rev-parse", "HEAD").stdout.trim());
  assert.equal(receipt.recorder.clean, true);
  assert.equal(receipt.journalSha256, sha256('{"type":"recipe-begin"}\n'));
  assert.equal(receipt.standinSha256, standinSha256());
  assert.equal(receipt.fixtureIndexSha256, sha256('{"recipes":[]}'));
  assert.equal(receipt.rulesSha256, sha256("rules"));
  assert.deepEqual(receipt.result, {
    status: "LOCAL_COMPLETE",
    completedRecipes: [26, 0],
    requests: 2446,
    exitCode: 0,
  });
  assert.deepEqual(JSON.parse(readFileSync(join(s.out, "receipt.json"), "utf8")), receipt);
  for (const name of ["fireemu.config.json", "firebase.json"])
    assert.ok(existsSync(join(s.out, name)), name);
  assert.equal(
    existsSync(join(s.out, "loopback.sb")),
    false,
    "no sandbox profile when the sandbox is off",
  );
});

test("a commit that is not a full SHA, a missing path or an unclean recorder is refused before anything runs", async () => {
  const s = setup();
  for (const commit of [undefined, "", "abc123", "B".repeat(40), `${COMMIT}0`])
    await assert.rejects(rehearse(input(s, { fireemuCommit: commit })), /full commit SHA/);
  for (const name of ["fireemuBinary", "recorderDir", "rulesFile", "fixtureDir"])
    await assert.rejects(
      rehearse(input(s, { [name]: join(s.root, "absent") })),
      new RegExp(`${name} does not exist`),
    );
  await assert.rejects(
    rehearse(input(s, { fireemuBinary: undefined })),
    /fireemuBinary does not exist/,
  );
  const dirty = setup({ clean: false });
  await assert.rejects(rehearse(input(dirty)), /not clean/);
  assert.equal(existsSync(join(dirty.out, "receipt.json")), false);
});

test("a rehearsal that reports no journal is refused, with the exit code", async () => {
  const s = setup({ script: "#!/bin/sh\necho nothing useful\nexit 3\n" });
  await assert.rejects(
    rehearse(input(s)),
    /did not report its journal \(exit 3\); stderr tail: ""/,
  );
  assert.equal(existsSync(join(s.out, "receipt.json")), false);
});

test("what the rehearsal wrote to stderr is in the error, truncated to its tail", async () => {
  const s = setup({
    script: `#!/bin/sh\necho "$(printf 'x%.0s' $(seq 1 400))END" >&2\nexit 4\n`,
  });
  await assert.rejects(rehearse(input(s)), (error) => {
    assert.match(error.message, /\(exit 4\); stderr tail: "x+END\\n"$/);
    assert.ok(error.message.length < 400);
    return true;
  });
});

test("a rehearsal that runs too long is stopped", async () => {
  const s = setup({ script: "#!/bin/sh\nsleep 30\n" });
  await assert.rejects(rehearse(input(s, { timeoutMs: 300 })), /timed out/);
});

test("a binary that cannot be run is an error", async () => {
  const s = setup();
  writeFileSync(s.binary, "not executable");
  chmodSync(s.binary, 0o644);
  // The spawn error is reported at once, not after the timeout.
  await assert.rejects(rehearse(input(s, { timeoutMs: 60_000 })), (error) => {
    assert.match(error.message, /EACCES|ENOENT|spawn/);
    assert.doesNotMatch(error.message, /timed out/);
    return true;
  });
});

test("the sandbox is on by default on macOS only, and the out directory's missing parents are created", async () => {
  const s = setup();
  const { sandbox: _ignored, ...rest } = input(s);
  const nested = join(s.root, "x", "y", "out");
  await rehearse({ ...rest, outDir: nested });
  assert.equal(existsSync(join(nested, "loopback.sb")), process.platform === "darwin");
});

test("a timed-out rehearsal takes its whole process group with it", async () => {
  const marker = join(tempDir("compare-group-"), "pid");
  const s = setup({ script: `#!/bin/sh\nsleep 30 &\necho $! > ${marker}\nwait\n` });
  await assert.rejects(rehearse(input(s, { timeoutMs: 600 })), /timed out/);
  const pid = Number(readFileSync(marker, "utf8"));
  assert.ok(pid > 1);
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
});

test("a recorder directory that is not a git checkout is refused, never taken as clean", async () => {
  const s = setup();
  const plain = join(s.root, "plain");
  mkdirSync(plain);
  await assert.rejects(
    rehearse(input(s, { recorderDir: plain })),
    /git rev-parse failed .*not a usable git checkout/,
  );
  assert.equal(existsSync(join(s.out, "receipt.json")), false);
  // A repository with no commit has no HEAD.
  const empty = join(s.root, "empty");
  mkdirSync(empty);
  git(empty, "init", "-q");
  await assert.rejects(rehearse(input(s, { recorderDir: empty })), /git rev-parse failed/);
});

test("git failing on the status of a checkout is an error too", async () => {
  const s = setup();
  // A checkout whose index is corrupt: rev-parse works, status does not.
  writeFileSync(join(s.recorder, ".git", "index"), "corrupt");
  await assert.rejects(rehearse(input(s)), /git status failed/);
});

test("the rehearsal leaves no timer behind, after a finished run or a failed spawn", async () => {
  const timers = () => process.getActiveResourcesInfo().filter((name) => name === "Timeout").length;
  const before = timers();
  const s = setup();
  await rehearse(input(s, { timeoutMs: 600_000 }));
  assert.equal(timers(), before);
  writeFileSync(s.binary, "not executable");
  chmodSync(s.binary, 0o644);
  await assert.rejects(rehearse(input(s, { timeoutMs: 600_000 })));
  assert.equal(timers(), before);
});

test("the rehearse command prints the receipt it wrote", async () => {
  const s = setup();
  const lines = [];
  const receipt = await rehearseCommand(
    {
      fireemu: s.binary,
      "fireemu-commit": COMMIT,
      recorder: s.recorder,
      rules: s.rules,
      fixture: s.fixture,
      out: s.out,
    },
    (line) => lines.push(line),
  );
  assert.equal(lines.length, 1);
  assert.equal(lines[0], JSON.stringify(receipt, null, 2));
  assert.match(lines[0], /\n {2}"/);
});
