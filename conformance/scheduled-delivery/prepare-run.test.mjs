// The preparation runner: the plan without --send, the refusals, and a send against the fake in the
// runner's own process (fetch and the long waits replaced), including its exit codes and files.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const runner = new URL("./prepare-run.mjs", import.meta.url).pathname;
const preload = new URL("./prepare-run-preload.mjs", import.meta.url).pathname;
const run = (args, env = { PATH: "/nonexistent" }) =>
  spawnSync(process.execPath, [runner, ...args], { encoding: "utf8", env });
const planDigest = () => {
  const out = run([]).stdout;
  return JSON.parse(out.slice(0, out.indexOf("}\n") + 1)).packetDigest;
};

test("without --send the runner prints the plan and sends nothing", () => {
  const out = run([]);
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /^\{\n {2}"project": "fireemu-oracle-sbx",\n/);
  const plan = JSON.parse(out.stdout.slice(0, out.stdout.indexOf("}\n") + 1));
  assert.equal(plan.targetServices.length, 8);
  assert.equal(plan.maxRequests, 60);
  assert.match(plan.packetDigest, /^[0-9a-f]{64}$/);
  assert.match(out.stdout, /plan only: nothing was sent/);
});

test("--send with another digest, without a run directory or with a bad number, refuses before any credential", () => {
  const wrong = run(["--send", "--expect-digest", "0".repeat(64)]);
  assert.equal(wrong.status, 2);
  assert.match(wrong.stderr, /digest differs/);
  const missing = run([
    "--send",
    "--expect-digest",
    planDigest(),
    "--project-number",
    "123456789012",
  ]);
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /--run-dir and --project-number are required/);
});

function send({ mode = "clean", number = "123456789012" } = {}) {
  const root = mkdtempSync(join(tmpdir(), "prep-run-"));
  const bin = join(root, "bin");
  mkdirSync(bin);
  writeFileSync(join(bin, "gcloud"), "#!/bin/sh\necho test-token\n");
  chmodSync(join(bin, "gcloud"), 0o755);
  const dir = join(root, "nested", "run");
  const out = spawnSync(
    process.execPath,
    [
      "--import",
      preload,
      runner,
      "--run-dir",
      dir,
      "--project-number",
      number,
      "--send",
      "--expect-digest",
      planDigest(),
    ],
    { encoding: "utf8", env: { PATH: bin, FAKE_MODE: mode } },
  );
  let files = [];
  try {
    files = readdirSync(dir);
  } catch {
    files = [];
  }
  return { out, dir, files, root };
}
const cleanup = (r) => rmSync(r.root, { recursive: true, force: true });

test("a clean send exits 0 and writes a private journal and an indented result", () => {
  const r = send();
  try {
    assert.equal(r.out.status, 0, r.out.stderr);
    const journalName = r.files.find((f) => /^journal-[0-9a-f]{16}\.jsonl$/.test(f));
    const resultName = r.files.find((f) => /^result-[0-9a-f]{16}\.json$/.test(f));
    assert.ok(journalName && resultName, r.files.join());
    assert.equal(journalName.slice(8, 24), resultName.slice(7, 23));
    assert.equal(statSync(r.dir).mode & 0o777, 0o700);
    assert.equal(statSync(join(r.dir, journalName)).mode & 0o777, 0o600);
    assert.equal(statSync(join(r.dir, resultName)).mode & 0o777, 0o600);
    const text = readFileSync(join(r.dir, resultName), "utf8");
    assert.equal(text, JSON.stringify(JSON.parse(text), null, 2) + "\n");
    assert.equal(JSON.parse(text).closureReady, true);
    const journal = readFileSync(join(r.dir, journalName), "utf8");
    assert.ok(journal.endsWith("\n"));
    const rows = journal
      .trimEnd()
      .split("\n")
      .map((l) => JSON.parse(l));
    assert.equal(rows[0].id, "identity");
    assert.ok(rows.some((x) => x.state === "issued" && x.serviceIds.length === 8));
    assert.equal(journal.split("\n").length - 1, rows.length);
    const rest = r.out.stdout.slice(r.out.stdout.indexOf("}\n") + 2);
    assert.equal(rest, JSON.stringify(JSON.parse(rest), null, 2) + "\n");
  } finally {
    cleanup(r);
  }
});

test("an unknown enable exits 3, a refused one exits 3 with the stop, a thrown collector exits 4", () => {
  const unknown = send({ mode: "unknown-enable" });
  try {
    assert.equal(unknown.out.status, 3, unknown.out.stderr);
    const result = JSON.parse(
      readFileSync(
        join(
          unknown.dir,
          unknown.files.find((f) => f.startsWith("result-")),
        ),
        "utf8",
      ),
    );
    assert.equal(result.readBackRequired, true);
    assert.equal(result.unknownMutations, 1);
  } finally {
    cleanup(unknown);
  }
  const denied = send({ mode: "denied" });
  try {
    assert.equal(denied.out.status, 3);
    const result = JSON.parse(
      readFileSync(
        join(
          denied.dir,
          denied.files.find((f) => f.startsWith("result-")),
        ),
        "utf8",
      ),
    );
    assert.equal(result.outcome, "scheduled-delivery-prepare-auth-stop");
  } finally {
    cleanup(denied);
  }
  const threw = send({ mode: "reflect" });
  try {
    assert.equal(threw.out.status, 4, threw.out.stderr);
    assert.ok(threw.out.stderr.startsWith("the collector stopped: "), threw.out.stderr);
    const text = readFileSync(
      join(
        threw.dir,
        threw.files.find((f) => f.startsWith("result-")),
      ),
      "utf8",
    );
    assert.equal(JSON.parse(text).outcome, "scheduled-delivery-prepare-collector-threw");
    assert.equal(text, JSON.stringify(JSON.parse(text), null, 2) + "\n");
  } finally {
    cleanup(threw);
  }
});

test("the project number is 12 or 13 digits", () => {
  for (const [number, ok] of [
    ["12345678901", false],
    ["123456789012", true],
    ["1234567890123", true],
    ["12345678901234", false],
  ]) {
    const r = send({ mode: "reflect", number });
    try {
      assert.equal(r.out.status, ok ? 4 : 2, number + ": " + r.out.stderr);
    } finally {
      cleanup(r);
    }
  }
});
