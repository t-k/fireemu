import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import test from "node:test";

const run = (args) =>
  spawnSync(
    process.execPath,
    [new URL("./calendar-v6-run.mjs", import.meta.url).pathname, ...args],
    {
      encoding: "utf8",
      env: { PATH: "/nonexistent" },
    },
  );

test("without --send the runner prints the plan and sends nothing", () => {
  const out = run([]);
  assert.equal(out.status, 0, out.stderr);
  const plan = JSON.parse(out.stdout.slice(0, out.stdout.indexOf("}\n") + 1));
  assert.equal(plan.project, "fireemu-oracle-sbx");
  assert.equal(plan.cases, 47);
  assert.match(plan.packetDigest, /^[0-9a-f]{64}$/);
  assert.match(out.stdout, /plan only: nothing was sent/);
});

test("--send with another digest, or without a run directory, refuses before any credential is read", () => {
  const wrong = run(["--send", "--expect-digest", "0".repeat(64)]);
  assert.equal(wrong.status, 2);
  assert.match(wrong.stderr, /digest differs/);
  const plan = JSON.parse(run([]).stdout.slice(0, run([]).stdout.indexOf("}\n") + 1));
  const missing = run(["--send", "--expect-digest", plan.packetDigest]);
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /--run-dir and --project-number are required/);
});

// ---- a send, against the fake (the runner's own process, fetch and waits replaced) ----------

import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const planDigest = () => {
  const out = run([]).stdout;
  return JSON.parse(out.slice(0, out.indexOf("}\n") + 1)).packetDigest;
};

/** Runs the runner with `--send` against the fake; `--run-dir` comes first on purpose. */
function send({ mode = "clean", number = "123456789012", runDir, extra = [] } = {}) {
  const root = mkdtempSync(join(tmpdir(), "cal6-run-"));
  const bin = join(root, "bin");
  mkdirSync(bin);
  writeFileSync(join(bin, "gcloud"), "#!/bin/sh\necho test-token\n");
  chmodSync(join(bin, "gcloud"), 0o755);
  const dir = runDir ?? join(root, "nested", "run");
  const out = spawnSync(
    process.execPath,
    [
      "--import",
      new URL("./calendar-v6-run-preload.mjs", import.meta.url).pathname,
      new URL("./calendar-v6-run.mjs", import.meta.url).pathname,
      "--run-dir",
      dir,
      "--project-number",
      number,
      "--send",
      "--expect-digest",
      planDigest(),
      ...extra,
    ],
    { encoding: "utf8", env: { PATH: bin, FAKE_MODE: mode } },
  );
  const files = (() => {
    try {
      return readdirSync(dir);
    } catch {
      return [];
    }
  })();
  return { out, dir, files, root };
}
const cleanup = (r) => rmSync(r.root, { recursive: true, force: true });

test("a clean send exits 0, writes a private journal and an indented result, and creates the run directory", () => {
  const r = send();
  try {
    assert.equal(r.out.status, 0, r.out.stderr);
    const journalName = r.files.find((f) => /^journal-[0-9a-f]{16}\.jsonl$/.test(f));
    const resultName = r.files.find((f) => /^result-[0-9a-f]{16}\.json$/.test(f));
    assert.ok(journalName && resultName, r.files.join());
    assert.equal(journalName.slice(8, 24), resultName.slice(7, 23), "one run id");
    assert.equal(statSync(r.dir).mode & 0o777, 0o700);
    assert.equal(statSync(join(r.dir, journalName)).mode & 0o777, 0o600);
    assert.equal(statSync(join(r.dir, resultName)).mode & 0o777, 0o600);
    const resultText = readFileSync(join(r.dir, resultName), "utf8");
    const result = JSON.parse(resultText);
    assert.equal(resultText, JSON.stringify(result, null, 2) + "\n");
    assert.equal(result.closureReady, true);
    assert.equal(result.unknownMutations, 0);
    const journal = readFileSync(join(r.dir, journalName), "utf8");
    assert.ok(journal.endsWith("\n"));
    const rows = journal
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line));
    assert.equal(rows[0].id, "identity");
    assert.equal(rows[0].state, "before-send");
    assert.ok(rows.some((row) => row.state === "issued" && row.name.includes("fe-cal6-")));
    assert.equal(journal.split("\n").length - 1, rows.length, "one row per line");
    // The plan comes first, then the result without its cases.
    const rest = r.out.stdout.slice(r.out.stdout.indexOf("}\n") + 2);
    const printed = JSON.parse(rest);
    assert.equal(rest, JSON.stringify(printed, null, 2) + "\n");
    assert.match(printed.runId, /^[0-9a-f]{16}$/);
    assert.equal(printed.cases, undefined);
  } finally {
    cleanup(r);
  }
});

test("a send whose answers need review exits 3 and still writes the result", () => {
  const r = send({ mode: "unknown-delete" });
  try {
    assert.equal(r.out.status, 3, r.out.stderr);
    const resultName = r.files.find((f) => f.startsWith("result-"));
    const result = JSON.parse(readFileSync(join(r.dir, resultName), "utf8"));
    assert.equal(result.closureReady, false);
    assert.equal(result.readBackRequired, true);
  } finally {
    cleanup(r);
  }
});

test("a collector that throws exits 4 and leaves a result that says so, after the journal", () => {
  const r = send({ mode: "reflect" });
  try {
    assert.equal(r.out.status, 4, r.out.stderr);
    assert.ok(r.out.stderr.startsWith("the collector stopped: "), r.out.stderr);
    const resultName = r.files.find((f) => f.startsWith("result-"));
    const text = readFileSync(join(r.dir, resultName), "utf8");
    const result = JSON.parse(text);
    assert.equal(result.outcome, "calendar-v6-collector-threw");
    assert.match(result.message, /credential/);
    assert.equal(text, JSON.stringify(result, null, 2) + "\n");
    assert.equal(statSync(join(r.dir, resultName)).mode & 0o777, 0o600);
    assert.ok(r.files.some((f) => f.startsWith("journal-")));
  } finally {
    cleanup(r);
  }
});

test("the project number is 12 or 13 digits and the run directory is required", () => {
  for (const [number, ok] of [
    ["12345678901", false],
    ["123456789012", true],
    ["1234567890123", true],
    ["12345678901234", false],
    ["12345678901a", false],
  ]) {
    const r = send({ mode: "reflect", number });
    try {
      assert.equal(r.out.status, ok ? 4 : 2, number + ": " + r.out.stderr);
    } finally {
      cleanup(r);
    }
  }
  const out = spawnSync(
    process.execPath,
    [
      new URL("./calendar-v6-run.mjs", import.meta.url).pathname,
      "--send",
      "--expect-digest",
      planDigest(),
      "--project-number",
      "123456789012",
    ],
    { encoding: "utf8", env: { PATH: "/nonexistent" } },
  );
  assert.equal(out.status, 2);
  assert.match(out.stderr, /--run-dir and --project-number are required/);
});

test("the plan is printed indented", () => {
  assert.match(run([]).stdout, /^\{\n {2}"project": "fireemu-oracle-sbx",\n/);
});
