import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import { requireCleanCheckout } from "./storage-rules-s9/run.mjs";
import { createLocalDeps, createProductionDeps, fetchNet } from "./storage-rules-s9/deps.mjs";
import { LOCAL_BUCKET, ROWS } from "./storage-rules-s9/plan.mjs";
import { createWorld } from "./storage-rules-s9/world.fake.mjs";

const run = new URL("./storage-rules-s9/run.mjs", import.meta.url).pathname;
const scratch = mkdtempSync(join(tmpdir(), "s9-cli-"));
after(() => rmSync(scratch, { recursive: true, force: true }));

const cli = (args, env = {}) =>
  spawnSync(process.execPath, [run, ...args], {
    encoding: "utf8",
    env: { PATH: process.env.PATH, ...env },
  });

/** The fake world behind a loopback HTTP server, for the real local path (fetch, argv, files). */
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

describe("storage rules s9 command line", () => {
  it("refuses an unknown command", () => {
    const result = cli(["nope"]);
    assert.notEqual(result.status, 0);
    assert.match(
      result.stderr,
      /usage: run.mjs record-production \| record-local \| readback \| table/,
    );
  });

  it("refuses to record in production under ambient credentials, without a baseline, or with a bad one", () => {
    const withEnv = cli(
      ["record-production", "--baseline", "absent", "--out", join(scratch, "a")],
      { GOOGLE_APPLICATION_CREDENTIALS: "/x" },
    );
    assert.notEqual(withEnv.status, 0);
    assert.match(withEnv.stderr, /refusing to start with GOOGLE_APPLICATION_CREDENTIALS set/);
    for (const name of ["FIREBASE_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN"]) {
      assert.match(
        cli(["record-production", "--baseline", "absent", "--out", join(scratch, "b")], {
          [name]: "x",
        }).stderr,
        /refusing to start/,
      );
    }
    assert.match(
      cli(["record-production", "--out", join(scratch, "c")]).stderr,
      /--baseline is required/,
    );
    assert.match(
      cli(["record-production", "--baseline", "present", "--out", join(scratch, "d")]).stderr,
      /baseline is neither/,
    );
    assert.match(
      cli([
        "record-production",
        "--baseline",
        "projects/other/rulesets/x",
        "--out",
        join(scratch, "e"),
      ]).stderr,
      /baseline is neither/,
    );
  });

  it("pins a production run to a commit of a clean worktree", () => {
    assert.doesNotThrow(() => requireCleanCheckout({ gitSha: "a".repeat(40), dirty: false }));
    assert.throws(
      () => requireCleanCheckout({ gitSha: "a".repeat(40), dirty: true }),
      /uncommitted or untracked/,
    );
    assert.throws(
      () => requireCleanCheckout({ gitSha: null, dirty: null }),
      /git state is unavailable/,
    );
  });

  it("needs an origin or an emulator host for a local record, and knows its rows", () => {
    assert.match(cli(["record-local", "--out", join(scratch, "f")]).stderr, /--origin is required/);
    assert.match(
      cli([
        "record-local",
        "--origin",
        "http://127.0.0.1:1",
        "--out",
        join(scratch, "g"),
        "--rows",
        "nope",
      ]).stderr,
      /unknown row nope/,
    );
  });

  it("records the whole plan against a loopback server, saves results and prints a table", async () => {
    const fake = createWorld({
      project: "demo-storage-s9",
      bucket: LOCAL_BUCKET,
      baseline: null,
      lag: 0,
    });
    const { server, origin } = await serve(fake);
    const out = join(scratch, "local");
    try {
      const child = spawn(
        process.execPath,
        [run, "record-local", "--origin", origin, "--out", out],
        { env: { PATH: process.env.PATH } },
      );
      let stdout = "";
      child.stdout.on("data", (chunk) => (stdout += chunk));
      const code = await new Promise((resolve) => child.on("exit", resolve));
      assert.equal(code, 0);
      const report = JSON.parse(stdout);
      assert.equal(report.stopped, null);
      assert.equal(report.complete, true);
      assert.equal(report.estimatedUsd, 0.05);
      assert.deepEqual(readdirSync(out).sort(), [
        "journal.jsonl",
        "results.json",
        "run-report.json",
      ]);
      const results = JSON.parse(readFileSync(join(out, "results.json"), "utf8"));
      assert.equal(results.rows.length, ROWS.length * 2);
      assert.equal(fake.world.objects.size, 0);
      // The journal never holds a credential: the local owner token is the literal `owner`, and v0 reads carry none.
      const journal = readFileSync(join(out, "journal.jsonl"), "utf8");
      assert.ok(!/Bearer/.test(journal));
      const table = cli(["table", "--run", `local=${out}`]);
      assert.equal(table.status, 0, table.stderr);
      const lines = table.stdout.split("\n");
      assert.equal(lines[0], "row\tplan\tlocal");
      assert.equal(lines[1], "pub-plain-meta\tallow\tallow/200");
      assert.ok(table.stdout.includes("\nload\tlocal\ns7-lone-surrogate\tloads/200"));
      assert.match(cli(["table"]).stderr, /--run label=dir is required/);
    } finally {
      server.close();
    }
  });

  it("limits a local record to the named rows and recordings", async () => {
    const fake = createWorld({
      project: "demo-storage-s9",
      bucket: LOCAL_BUCKET,
      baseline: null,
      lag: 0,
    });
    const { server, origin } = await serve(fake);
    const out = join(scratch, "filtered");
    try {
      const child = spawn(
        process.execPath,
        [
          run,
          "record-local",
          "--origin",
          origin,
          "--out",
          out,
          "--rows",
          "c1-true,den-meta",
          "--recordings",
          "1",
        ],
        { env: { PATH: process.env.PATH } },
      );
      const code = await new Promise((resolve) => child.on("exit", resolve));
      assert.equal(code, 0);
      const results = JSON.parse(readFileSync(join(out, "results.json"), "utf8"));
      assert.deepEqual(results.rows.map((row) => row.id).sort(), ["c1-true", "den-meta"]);
    } finally {
      server.close();
    }
  });
});

describe("storage rules s9 network dependencies", () => {
  async function origin(handler) {
    const server = http.createServer(handler);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    return { server, url: `http://127.0.0.1:${server.address().port}` };
  }

  it("returns status, lower-case headers and exact bytes, and does not follow a redirect", async () => {
    const { server, url } = await origin((req, res) => {
      if (req.url === "/redirect") {
        res.writeHead(302, { Location: "/other" });
        res.end();
      } else {
        res.writeHead(200, { "X-Thing": "1" });
        res.end(Buffer.from([0, 255, 10]));
      }
    });
    try {
      const ok = await fetchNet({ method: "GET", url: `${url}/x`, headers: {} });
      assert.equal(ok.status, 200);
      assert.equal(ok.headers["x-thing"], "1");
      assert.deepEqual([...ok.body], [0, 255, 10]);
      const redirected = await fetchNet({ method: "GET", url: `${url}/redirect`, headers: {} });
      assert.equal(redirected.status, 302);
    } finally {
      server.close();
    }
  });

  it("times out instead of waiting for a silent server", async () => {
    const { server, url } = await origin(() => {});
    try {
      await assert.rejects(fetchNet({ method: "GET", url, headers: {}, timeoutMs: 50 }));
    } finally {
      server.closeAllConnections();
      server.close();
    }
  });

  it("sends production requests through the lease, with the owner headers", async () => {
    const steps = [];
    const lease = {
      verifyHeld: async () => steps.push("verify"),
      dispatch: async (work) => {
        steps.push("dispatch");
        return work();
      },
    };
    const { server, url } = await origin((req, res) => {
      res.writeHead(204);
      res.end();
    });
    try {
      const deps = createProductionDeps({ accessToken: "tok", lease });
      assert.deepEqual(deps.adminHeaders(), {
        authorization: "Bearer tok",
        "x-goog-user-project": "fireemu-oracle-query",
      });
      const answer = await deps.net({ method: "GET", url, headers: {} });
      assert.equal(answer.status, 204);
      assert.deepEqual(steps, ["verify", "dispatch"]);
      assert.deepEqual(createLocalDeps().adminHeaders(), { authorization: "Bearer owner" });
    } finally {
      server.close();
    }
    writeFileSync(join(scratch, "marker"), "x");
  });
});
