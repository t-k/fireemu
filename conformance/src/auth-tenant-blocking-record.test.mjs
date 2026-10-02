// The runner's steps up to its started line, run end to end against a fake sandbox (review-3
// Should-A): the signal handlers are in place before the signJwt wait, the wait gets the
// runner's signal, a signal during the last attempt still stops the run, and a run that wrote
// its started line is not noted as stopped before it.
//
// `run.mjs record-production` runs as a child process. `git` and `gcloud` are fake scripts on
// its PATH, and `fetch` is replaced by a preloaded fake that answers from memory: nothing leaves
// the machine. The ledger and its lock are temporary files shaped as the reviewed wrapper
// writes them, with this test process as the wrapper and the campaign.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { tempDir } from "./test-tmpdir.mjs";

const RUNNER = join(import.meta.dirname, "auth-tenant-blocking", "run.mjs");

/** A fake `fetch`: signJwt answers per FAKE_SIGNJWT, everything else a 400 refusal. */
const FAKE_FETCH = `
import { appendFileSync } from "node:fs";
const log = process.env.FAKE_FETCH_LOG;
let signJwt = 0;
globalThis.fetch = async (url) => {
  const { hostname, pathname } = new URL(String(url));
  appendFileSync(log, hostname + pathname + "\\n");
  if (hostname === "iamcredentials.googleapis.com") {
    signJwt += 1;
    const mode = process.env.FAKE_SIGNJWT;
    if (mode === "signal-on-200") {
      // The signal arrives while the admitted attempt is answered.
      process.kill(process.pid, "SIGTERM");
      await new Promise((resolve) => setTimeout(resolve, 100));
      return new Response(JSON.stringify({ signedJwt: "a.b.c" }), { status: 200 });
    }
    if (mode === "403") return new Response("{}", { status: 403 });
    return new Response(JSON.stringify({ signedJwt: "a.b.c" }), { status: 200 });
  }
  return new Response(JSON.stringify({ error: { code: 400, message: "FAKE_REFUSAL" } }), {
    status: 400,
  });
};
`;

async function sandbox() {
  const root = tempDir("atb-record-");
  const repo = join(root, "repo");
  const runs = join(repo, "docs.local", "runs");
  await mkdir(runs, { recursive: true });
  await mkdir(join(repo, ".git"));
  const ledger = join(runs, "sandbox-ledger.jsonl");
  await writeFile(ledger, "");
  const nonce = randomBytes(32).toString("hex");
  await writeFile(
    `${ledger}.lock`,
    JSON.stringify({
      pid: process.pid,
      nonceSha256: createHash("sha256").update(nonce).digest("hex"),
    }),
  );
  const bin = join(root, "bin");
  await mkdir(bin);
  // git: the common dir of the fake repository, a clean tree, a HEAD, and no repository
  // around the private directory.
  await writeFile(
    join(bin, "git"),
    `#!/bin/sh
case "$*" in
  *--git-common-dir*) echo "${join(repo, ".git")}" ;;
  *"status --porcelain"*) ;;
  *"rev-parse HEAD"*) echo 0000000000000000000000000000000000000000 ;;
  *--show-toplevel*) exit 128 ;;
  *) exit 2 ;;
esac
`,
  );
  await writeFile(join(bin, "gcloud"), "#!/bin/sh\necho ya29.fake-owner-token\n");
  await chmod(join(bin, "git"), 0o755);
  await chmod(join(bin, "gcloud"), 0o755);
  const web = join(root, "web.json");
  await writeFile(
    web,
    JSON.stringify({
      projectId: "fireemu-oracle-idp",
      projectNumber: "637500000000",
      messagingSenderId: "637500000000",
      apiKey: "AIzaFAKEKEYFORTESTSONLY",
    }),
  );
  const preload = join(root, "fake-fetch.mjs");
  await writeFile(preload, FAKE_FETCH);
  const fetchLog = join(root, "fetch.log");
  await writeFile(fetchLog, "");
  return { root, ledger, nonce, bin, web, preload, fetchLog };
}

/** Starts the runner; `onFetch` sees each request line as it is sent. */
async function runner(box, signJwtMode, onFetch = () => {}) {
  const child = spawn(process.execPath, ["--import", box.preload, RUNNER, "record-production"], {
    env: {
      PATH: `${box.bin}:/usr/bin:/bin`,
      HOME: box.root,
      AUTH_TENANT_SUITE: "tenant",
      FIREEMU_SANDBOX_LEDGER: box.ledger,
      FIREEMU_SANDBOX_LOCK_NONCE: box.nonce,
      FIREEMU_SANDBOX_WRAPPER_PID: String(process.pid),
      FIREEMU_AUTH_CAMPAIGN_PID: String(process.pid),
      FIREEMU_AUTH_TENANT_PRIVATE_DIR: join(box.root, "private"),
      FIREEMU_AUTH_SANDBOX_WEB_CONFIG: box.web,
      FIREEMU_AUTH_TENANT_REQUEST_BUDGET: "1800",
      FAKE_FETCH_LOG: box.fetchLog,
      FAKE_SIGNJWT: signJwtMode,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk) => (output += chunk));
  child.stderr.on("data", (chunk) => (output += chunk));
  let seen = 0;
  const poll = setInterval(async () => {
    const lines = (await readFile(box.fetchLog, "utf8")).split("\n").filter(Boolean);
    for (const line of lines.slice(seen)) onFetch(line, child);
    seen = lines.length;
  }, 20);
  const code = await new Promise((resolve) =>
    child.on("exit", (status, signal) => resolve({ status, signal })),
  );
  clearInterval(poll);
  const rows = (await readFile(box.ledger, "utf8"))
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  return { code, rows, output };
}

test(
  "a signal during the signJwt wait ends it at once and the charged requests are noted",
  { timeout: 20_000 },
  async () => {
    const box = await sandbox();
    let signalled = false;
    const started = Date.now();
    const { code, rows, output } = await runner(box, "403", (line, child) => {
      if (!signalled && line.startsWith("iamcredentials.googleapis.com")) {
        signalled = true;
        child.kill("SIGTERM");
      }
    });
    // The handler was in place (the runner was not killed by the signal) and the wait got
    // the runner's signal (it did not sit out the 30 s interval).
    assert.equal(code.signal, null, output);
    assert.notEqual(code.status, 0, output);
    assert.ok(Date.now() - started < 15_000, output);
    assert.deepEqual(
      rows.map((row) => [row.event, row.beforeStarted]),
      [["control", true]],
      output,
    );
    assert.match(rows[0].error, /stopped by a signal before the recording started/);
    // The owner token (3) and one signJwt attempt.
    assert.equal(rows[0].requests, 4);
  },
);

test(
  "a signal during the admitted signJwt attempt still stops before the started line",
  { timeout: 20_000 },
  async () => {
    const box = await sandbox();
    const { code, rows, output } = await runner(box, "signal-on-200");
    assert.equal(code.signal, null, output);
    assert.notEqual(code.status, 0, output);
    assert.deepEqual(
      rows.map((row) => [row.event, row.beforeStarted]),
      [["control", true]],
      output,
    );
    assert.match(rows[0].error, /stopped by a signal before the recording started/);
  },
);

test(
  "a run that wrote its started line is never noted as stopped before it",
  { timeout: 60_000 },
  async () => {
    const box = await sandbox();
    const { rows, output } = await runner(box, "200");
    assert.equal(rows[0]?.event, "started", output);
    assert.ok(
      rows.every((row) => row.beforeStarted === undefined),
      JSON.stringify(rows, null, 2),
    );
    // The run failed against the fake sandbox and its terminal line accounts for it.
    assert.ok(
      rows.some((row) => row.outcome !== undefined),
      JSON.stringify(rows, null, 2),
    );
  },
);
