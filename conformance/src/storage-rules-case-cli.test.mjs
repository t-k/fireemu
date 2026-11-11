import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import { CASE_PLAN, CASE_ROWS } from "./storage-rules-s9/plan-case.mjs";
import { createWorld } from "./storage-rules-s9/world.fake.mjs";

const run = new URL("./storage-rules-s9/run.mjs", import.meta.url).pathname;
const scratch = mkdtempSync(join(tmpdir(), "case-cli-"));
after(() => rmSync(scratch, { recursive: true, force: true }));

const cli = (args, env = {}) =>
  spawnSync(process.execPath, [run, ...args], {
    encoding: "utf8",
    env: { PATH: process.env.PATH, ...env },
  });

async function serve(world) {
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", async () => {
      const answer = await world.net({
        method: req.method,
        url: `http://${req.headers.host}${req.url}`,
        headers: req.headers,
        body: Buffer.concat(chunks),
      });
      res.writeHead(answer.status, answer.headers);
      res.end(answer.body);
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, origin: `http://127.0.0.1:${server.address().port}` };
}

describe("storage rules case command line", () => {
  it("refuses every sending command without a known --plan", () => {
    for (const command of ["record-production", "record-local", "table"]) {
      assert.match(cli([command]).stderr, /--plan is required/, command);
      assert.match(cli([command, "--plan", "nope"]).stderr, /unknown plan nope/, command);
    }
    assert.match(cli(["recover"]).stderr, /--run-dir is required/);
  });

  it("records the case plan against a loopback server and reads it with the table command", async () => {
    const fake = createWorld({
      plan: CASE_PLAN,
      project: "demo-storage-case",
      bucket: CASE_PLAN.localBucket,
      baseline: null,
      lag: 0,
    });
    const { server, origin } = await serve(fake);
    const out = join(scratch, "local");
    try {
      const child = spawn(
        process.execPath,
        [run, "record-local", "--plan", "case", "--origin", origin, "--out", out],
        { env: { PATH: process.env.PATH } },
      );
      let stdout = "";
      child.stdout.on("data", (chunk) => (stdout += chunk));
      assert.equal(await new Promise((resolve) => child.on("exit", resolve)), 0);
      const report = JSON.parse(stdout);
      assert.equal(report.plan, "case");
      assert.equal(report.complete, true);
      assert.equal(report.estimatedUsd, CASE_PLAN.estimatedUsd);
      assert.deepEqual(readdirSync(out).toSorted(), [
        "journal.jsonl",
        "results.json",
        "run-report.json",
      ]);
      assert.equal(
        JSON.parse(readFileSync(join(out, "results.json"), "utf8")).rows.length,
        CASE_ROWS.length * 2,
      );
      assert.equal(fake.world.objects.size, 0);
      const table = cli(["table", "--plan", "case", "--run", `local=${out}`]);
      assert.equal(table.status, 0, table.stderr);
      assert.match(table.stdout, /^== local\nverdict: ascii\n/);
      assert.match(table.stdout, /\nacute-lower-same\tacute\tallow,allow\tallow\tdeny\tdeny\n/);
    } finally {
      server.close();
    }
  });

  it("reads a one-recording run as complete and separates the runs of a table by a blank line", async () => {
    const fake = createWorld({
      plan: CASE_PLAN,
      project: "demo-storage-case",
      bucket: CASE_PLAN.localBucket,
      baseline: null,
      lag: 0,
    });
    const { server, origin } = await serve(fake);
    const out = join(scratch, "one");
    try {
      const child = spawn(
        process.execPath,
        [
          run,
          "record-local",
          "--plan",
          "case",
          "--origin",
          origin,
          "--out",
          out,
          "--recordings",
          "1",
        ],
        { env: { PATH: process.env.PATH } },
      );
      assert.equal(await new Promise((resolve) => child.on("exit", resolve)), 0);
      const table = cli(["table", "--plan", "case", "--run", `a=${out}`, "--run", `b=${out}`]);
      assert.equal(table.status, 0, table.stderr);
      assert.match(table.stdout, /^== a\nverdict: ascii\ncomplete: true; controls: ok\n/);
      assert.match(table.stdout, /\n\n== b\nverdict: ascii\n/);
      assert.ok(
        table.stdout.includes("\tallow\tallow\tallow\n") ||
          table.stdout.includes("\tallow\tallow\tallow"),
      );
      assert.match(table.stdout, /\nacute-lower-same\tacute\tallow\tallow\tdeny\tdeny\n/);
    } finally {
      server.close();
    }
  });

  it("reads a run with no rows as incomplete, never as a candidate", () => {
    const dir = join(scratch, "empty");
    mkdirSync(dir);
    writeFileSync(join(dir, "results.json"), JSON.stringify({ rows: [], loads: [] }));
    const table = cli(["table", "--plan", "case", "--run", `e=${dir}`]);
    assert.equal(table.status, 0, table.stderr);
    assert.match(table.stdout, /^== e\nverdict: incomplete\n/);
  });

  it("refuses a row the plan does not have, and knows the case rows", () => {
    assert.match(
      cli([
        "record-local",
        "--plan",
        "case",
        "--origin",
        "http://127.0.0.1:1",
        "--out",
        join(scratch, "x"),
        "--rows",
        "c1-true",
      ]).stderr,
      /unknown row c1-true/,
    );
  });
});
