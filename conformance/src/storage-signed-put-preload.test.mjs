// The network sentinel is a preload every test file of this lane imports first (Opus S4): any
// attempted request outside loopback is refused and recorded, and the file fails at exit even if
// the code under test swallowed the error.

import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import https from "node:https";
import { describe, it } from "node:test";

import { attempts } from "./storage-signed-put/test-preload.mjs";

const here = new URL(".", import.meta.url);

describe("network sentinel preload", () => {
  it("every storage-signed-put test file imports it before anything else", () => {
    const files = readdirSync(here).filter((f) => /^storage-signed-put-.*\.test\.mjs$/.test(f));
    assert.ok(files.length >= 10, files.join());
    for (const file of files) {
      const first = readFileSync(new URL(file, here), "utf8")
        .split("\n")
        .find((line) => /^\s*import\b/.test(line));
      assert.equal(first.trim(), 'import "./storage-signed-put/test-preload.mjs";', file);
    }
  });

  it("refuses and records requests outside loopback, whatever the call form", () => {
    assert.throws(() => https.request("https://probe.invalid/"), /egress refused/);
    assert.throws(() => globalThis.fetch("https://probe.invalid/storage/v1/b/x"), /not allowed/);
    assert.deepEqual(attempts, [
      "http: probe.invalid",
      "fetch: https://probe.invalid/storage/v1/b/x",
    ]);
    attempts.length = 0;
  });

  it("lets loopback through and records nothing for it", async () => {
    await assert.rejects(
      fetch("http://127.0.0.1:1/"),
      (error) => !/not allowed/.test(error.message),
    );
    assert.deepEqual(attempts, []);
  });

  it("fails a file that attempted a request and swallowed the error, and passes one that did not", () => {
    const dir = mkdtempSync(join(tmpdir(), "sp-preload-"));
    try {
      const preload = new URL("./storage-signed-put/test-preload.mjs", import.meta.url).href;
      const run = (name, body) => {
        const file = join(dir, name);
        writeFileSync(
          file,
          `import ${JSON.stringify(preload)};\nimport https from "node:https";\nimport { it } from "node:test";\nit("body", async () => { ${body} });\n`,
        );
        const env = { ...process.env };
        delete env.NODE_TEST_CONTEXT;
        return spawnSync(process.execPath, ["--test", file], {
          encoding: "utf8",
          timeout: 60_000,
          env,
        });
      };
      assert.equal(run("quiet.test.mjs", "").status, 0);
      const swallowedHttp = run(
        "http.test.mjs",
        'try { https.request("https://probe.invalid/"); } catch {}',
      );
      assert.notEqual(swallowedHttp.status, 0);
      assert.match(
        swallowedHttp.stdout + swallowedHttp.stderr,
        /a real network request was attempted/,
      );
      const swallowedFetch = run(
        "fetch.test.mjs",
        'try { await fetch("https://probe.invalid/"); } catch {}',
      );
      assert.notEqual(swallowedFetch.status, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
