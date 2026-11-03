import "./storage-signed-put/test-preload.mjs";

// The command line of the recorder (run.mjs), driven as a child process. Every case here ends
// before any network request: a refusal, a stub `gcloud` that fails, or the offline `compare`.

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const RUN = fileURLToPath(new URL("./storage-signed-put/run.mjs", import.meta.url));
const REPO = fileURLToPath(new URL("../..", import.meta.url));
const SIGNER = "firebase-adminsdk-fbsvc@fireemu-oracle-query.iam.gserviceaccount.com";
const MEMBER = "user:owner@example.com";

const tree = mkdtempSync(join(tmpdir(), "sp-run-"));
const stubBin = join(tree, "bin");
mkdirSync(stubBin);
// A `gcloud` that fails, so a run that gets as far as the ADC token stops there.
writeFileSync(join(stubBin, "gcloud"), "#!/bin/sh\nexit 1\n");
chmodSync(join(stubBin, "gcloud"), 0o755);

function cli(args, { env = {}, cwd = tree } = {}) {
  const base = { PATH: `${stubBin}:${process.env.PATH}`, HOME: tree };
  const result = spawnSync(process.execPath, [RUN, ...args], {
    encoding: "utf8",
    cwd,
    timeout: 60_000,
    env: { ...base, ...env },
  });
  return { status: result.status, text: `${result.stdout}${result.stderr}` };
}

const dirty = () =>
  execFileSync("git", ["-C", REPO, "status", "--porcelain"], { encoding: "utf8" }).trim() !== "";
const out = () => join(tree, `out-${Math.random().toString(16).slice(2)}`);
const good = (dir) => ["record-production", "--signer", SIGNER, "--member", MEMBER, "--out", dir];

describe("run.mjs command line", () => {
  it("names the commands when given none or an unknown one", () => {
    for (const args of [[], ["bogus"]]) {
      const run = cli(args);
      assert.notEqual(run.status, 0);
      assert.match(
        run.text,
        /usage: run\.mjs record-production \| record-local \| readback \| iam-remove \| compare/,
      );
    }
  });

  it("refuses to start with a credential variable set, before creating anything", () => {
    for (const env of [
      { GOOGLE_APPLICATION_CREDENTIALS: "/nonexistent" },
      { FIREBASE_TOKEN: "x" },
      { CLOUDSDK_CONFIG: "/nonexistent" },
      { CLOUDSDK_CORE_PROJECT: "x" },
    ]) {
      const dir = out();
      const run = cli(good(dir), { env });
      assert.notEqual(run.status, 0);
      assert.match(run.text, new RegExp(`refusing to start with ${Object.keys(env)[0]} set`));
      assert.equal(existsSync(dir), false);
    }
  });

  it("refuses a signer, member, window or output that is missing or wrong, before creating anything", () => {
    const refused = [
      [
        ["record-production", "--signer", "bad@example.com", "--member", MEMBER, "--out"],
        /signer is not a service account/,
      ],
      [
        ["record-production", "--signer", SIGNER, "--member", "user:Owner@example.com", "--out"],
        /member must be user/,
      ],
      [
        ["record-production", "--signer", SIGNER, "--member", "allUsers", "--out"],
        /member must be user/,
      ],
      [
        [
          "record-production",
          "--signer",
          SIGNER,
          "--member",
          MEMBER,
          "--window-minutes",
          "5",
          "--out",
        ],
        /window must be/,
      ],
      [
        [
          "record-production",
          "--signer",
          SIGNER,
          "--member",
          MEMBER,
          "--window-minutes",
          "abc",
          "--out",
        ],
        /window must be/,
      ],
    ];
    for (const [args, pattern] of refused) {
      const dir = out();
      const run = cli([...args, dir]);
      assert.notEqual(run.status, 0, args.join(" "));
      assert.match(run.text, pattern);
      assert.equal(existsSync(dir), false);
    }
    const noMember = cli(["record-production", "--signer", SIGNER, "--out", out()]);
    assert.match(noMember.text, /--member is required/);
    const noOut = cli(["record-production", "--signer", SIGNER, "--member", MEMBER]);
    // the dirty-worktree refusal comes before the output directory is read
    assert.match(noOut.text, dirty() ? /uncommitted or untracked files/ : /--out is required/);
  });

  it(
    "refuses a worktree with an untracked file, and goes on to the ADC token in a clean one",
    { skip: dirty() && "the checkout is not clean" },
    () => {
      const stray = join(REPO, "conformance", `stray-${process.pid}.txt`);
      try {
        writeFileSync(stray, "x");
        const dir = out();
        const run = cli(good(dir));
        assert.notEqual(run.status, 0);
        assert.match(run.text, /whole worktree\) has uncommitted or untracked files/);
        assert.equal(existsSync(dir), false);
      } finally {
        rmSync(stray, { force: true });
      }
      const dir = out();
      const run = cli(good(dir));
      assert.notEqual(run.status, 0);
      assert.match(run.text, /ADC token acquisition failed/);
      assert.equal(
        existsSync(join(tree, "docs.local")),
        false,
        "no lock or ledger is created before the token",
      );
    },
  );

  it("record-local needs the emulator host", () => {
    const run = cli(["record-local", "--out", out()]);
    assert.notEqual(run.status, 0);
    assert.match(run.text, /fireemu exec --only storage/);
  });

  it("readback and iam-remove need a run directory", () => {
    for (const command of ["readback", "iam-remove"]) {
      const run = cli([command]);
      assert.notEqual(run.status, 0);
      assert.match(run.text, /--run-dir is required/);
    }
  });

  it("compare lists matching and differing rows and writes comparison.json once", () => {
    const row = (extra = {}) => ({
      recording: 1,
      id: "a",
      status: 403,
      code: "X",
      shape: "xml-error",
      bodyBytes: 3,
      bodySha256: "11".repeat(32),
      body: "aaa",
      headers: {},
      ...extra,
    });
    const write = (name, rows) => {
      const dir = join(tree, name);
      mkdirSync(dir);
      writeFileSync(join(dir, "results.json"), JSON.stringify({ rows }));
      return dir;
    };
    const production = write("p", [row(), row({ id: "b" })]);
    const local = write("l", [
      row(),
      row({
        id: "b",
        status: 200,
        bodyBytes: 0,
        body: "",
        code: null,
        shape: "empty",
        bodySha256: "22".repeat(32),
      }),
    ]);
    const dir = out();
    const run = cli(["compare", "--production", production, "--local", local, "--out", dir]);
    assert.equal(run.status, 0, run.text);
    assert.deepEqual(JSON.parse(run.text.trim().split("\n").at(-1)), [
      ["a", "match"],
      ["b", "status+code+shape+bodyBytes+body"],
    ]);
    const saved = JSON.parse(readFileSync(join(dir, "comparison.json"), "utf8"));
    assert.deepEqual([saved.matching, saved.differing], [1, 1]);
    const again = cli(["compare", "--production", production, "--local", local, "--out", dir]);
    assert.notEqual(again.status, 0, "an existing output directory is not reused");
  });
});
