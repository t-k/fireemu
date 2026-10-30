import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { campaignPlan, judgeExport } from "./rtdb-release-replay.mjs";

const paths = ["rest-old", "ondisconnect", "auth", "residual", "s5", "functions", "rest-v033"];
test("each comparison resolves to its actual local producer and installed binary", () => {
  for (const name of paths) {
    const plan = campaignPlan(name, "/installed/fireemu", "/output");
    assert.ok(plan, name);
    assert.ok(plan.argv.includes("/installed/fireemu"), name);
    assert.ok(plan.argv.includes("local") || name === "functions", name);
  }
  assert.equal(campaignPlan("unknown", "/installed/fireemu", "/output"), undefined);
  for (const name of ["toString", "__proto__", "constructor"])
    assert.equal(campaignPlan(name, "/installed/fireemu", "/output"), undefined);
  assert.deepEqual(
    campaignPlan("rest-old", "/installed/fireemu", "/output"),
    campaignPlan("rest-v033", "/installed/fireemu", "/output"),
  );
});
test("result binding and verdict reject missing, changed or mismatched observations", () => {
  const hash = "a".repeat(64);
  const good = { campaign: "auth", binarySha256: hash, match: true };
  assert.deepEqual(judgeExport("auth", good, hash), []);
  for (const bad of [
    undefined,
    {},
    { ...good, match: false },
    { ...good, binarySha256: "b".repeat(64) },
    { ...good, campaign: "rest" },
  ])
    assert.notDeepEqual(judgeExport("auth", bad, hash), []);
});
test(
  "PICT generated runner and binary failures cannot pass",
  { skip: !process.env.RTDB_PICT_ROWS },
  () => {
    const rows = readFileSync(process.env.RTDB_PICT_ROWS, "utf8")
      .trim()
      .split("\n")
      .slice(1)
      .map((line) => line.split("\t"));
    assert.equal(rows.length, 31);
    const rest = JSON.parse(
      readFileSync(
        new URL(
          "../../spec/compatibility/closure/evidence/RTDB-rest-v033-comparison.json",
          import.meta.url,
        ),
      ),
    );
    for (const [name, runner, binary, result] of rows) {
      const expected = runner === "correct" && binary === "correct" && result === "match";
      const planned = campaignPlan(name, "/installed/fireemu", "/output");
      const campaign = planned?.campaign;
      const actual = judgeExport(
        name,
        result === "missing"
          ? undefined
          : {
              campaign: runner === "correct" ? campaign : "wrong",
              binarySha256: binary === "correct" ? "a".repeat(64) : "b".repeat(64),
              match: result === "match",
              result: rest,
            },
        "a".repeat(64),
      );
      assert.equal(actual.length === 0, expected, `${name}/${runner}/${binary}/${result}`);
    }
  },
);

test("the actual Web and Admin CRUD smoke runs through the installed binary", () => {
  const plan = campaignPlan("smoke", "/installed/fireemu", "/output");
  assert.deepEqual(plan.argv, [
    "/installed/fireemu",
    "exec",
    "--no-config-discovery",
    "--only",
    "database",
    "--",
    process.execPath,
    "tools/sdk-smoke-database/run.mjs",
    "--only",
    "crud",
  ]);
});

test("REST adjudication refuses substituted or missing recorded rows", async () => {
  const { mkdtempSync, rmSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { adjudicate } = await import("./rtdb-release-replay.mjs");
  const dir = mkdtempSync(join(tmpdir(), "rtdb-judge-"));
  try {
    const evidence = JSON.parse(
      readFileSync(
        new URL(
          "../../spec/compatibility/closure/evidence/RTDB-rest-v033-comparison.json",
          import.meta.url,
        ),
      ),
    );
    const save = () => writeFileSync(join(dir, "comparison.json"), JSON.stringify(evidence));
    save();
    assert.equal(adjudicate("rest", dir).match, true);
    evidence.rows[0].local = { status: 599, bodyText: "corrupt local content", etag: "wrong" };
    save();
    assert.equal(adjudicate("rest", dir).match, false);
    evidence.rows[0] = JSON.parse(
      readFileSync(
        new URL(
          "../../spec/compatibility/closure/evidence/RTDB-rest-v033-comparison.json",
          import.meta.url,
        ),
      ),
    ).rows[0];
    evidence.rows[0].id = "wrong";
    save();
    assert.equal(adjudicate("rest", dir).match, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("campaign selection pins the actual distinct producer scripts", () => {
  const expected = {
    "rest-old": "rest-replay.mjs",
    "rest-v033": "rest-replay.mjs",
    ondisconnect: "cv07-ondisconnect.mjs",
    auth: "cv11-genuine-auth.mjs",
    residual: "rtdb-residual.mjs",
    s5: "rtdb-s5.mjs",
    functions: "local-run.mjs",
  };
  for (const [name, script] of Object.entries(expected))
    assert.ok(
      campaignPlan(name, "/installed/fireemu", "/output").argv[1].endsWith(`/${script}`),
      name,
    );
});

test("recorded SDK journals and Functions frames are recomputed, and altered results fail", async () => {
  const { mkdtempSync, rmSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { adjudicate } = await import("./rtdb-release-replay.mjs");
  const dir = mkdtempSync(join(tmpdir(), "rtdb-judge-"));
  try {
    for (const [campaign, filename] of [
      ["auth", "production-cv11-genuine-auth.json"],
      ["residual", "production-rtdb-residual.json"],
      ["s5", "production-rtdb-s5.json"],
    ]) {
      const fixture = JSON.parse(
        readFileSync(
          new URL(`../../tools/sdk-smoke-database/fixtures/${filename}`, import.meta.url),
        ),
      );
      writeFileSync(join(dir, "journal.json"), JSON.stringify(fixture));
      assert.equal(adjudicate(campaign, dir).match, true, campaign);
      fixture.profiles.pop();
      writeFileSync(join(dir, "journal.json"), JSON.stringify(fixture));
      let passed = false;
      try {
        passed = adjudicate(campaign, dir).match === true;
      } catch {}
      assert.equal(passed, false, campaign);
    }
    const fixture = JSON.parse(
      readFileSync(
        new URL("./rtdb-functions/recorded/production-rtdb-triggers.json", import.meta.url),
      ),
    );
    const frames = fixture.frames.map(({ n: _n, step: _step, ...frame }) => frame);
    const writeFrames = () =>
      writeFileSync(
        join(dir, "frames.jsonl"),
        frames.map((f) => JSON.stringify(f)).join("\n") + "\n",
      );
    writeFileSync(
      join(dir, "writes.json"),
      JSON.stringify(
        Array.from({ length: 9 }, (_, i) => ({ step: `s${i + 1}`, n: i + 1, status: 200 })),
      ),
    );
    writeFrames();
    assert.equal(adjudicate("functions", dir).match, true);
    const writes = Array.from({ length: 9 }, (_, i) => ({
      step: `s${i + 1}`,
      n: i + 1,
      status: 200,
    }));
    writes[8].step = "s1";
    writeFileSync(join(dir, "writes.json"), JSON.stringify(writes));
    assert.equal(adjudicate("functions", dir).match, false);
    writes[8].step = "s9";
    writeFileSync(join(dir, "writes.json"), JSON.stringify(writes));
    frames.pop();
    writeFrames();
    assert.equal(adjudicate("functions", dir).match, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the browser SDK runtime resources reject changed or missing recorded versions", async () => {
  const { mkdtempSync, mkdirSync, rmSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { runtimeResources } = await import("./rtdb-release-replay.mjs");
  const dir = mkdtempSync(join(tmpdir(), "rtdb-resources-"));
  try {
    for (const [name, version] of [
      ["firebase", "12.18.0"],
      ["firebase-admin", "14.3.0"],
      ["playwright", "1.62.1"],
    ]) {
      mkdirSync(join(dir, "node_modules", name), { recursive: true });
      writeFileSync(join(dir, "node_modules", name, "package.json"), JSON.stringify({ version }));
    }
    for (const name of ["firebase-app.js", "firebase-auth.js", "firebase-database.js"])
      writeFileSync(join(dir, "node_modules", "firebase", name), name);
    writeFileSync(join(dir, "package-lock.json"), "{}");
    const hashes = runtimeResources("auth", dir);
    assert.match(hashes["node_modules/firebase/firebase-auth.js"], /^[a-f0-9]{64}$/);
    writeFileSync(
      join(dir, "node_modules", "firebase", "package.json"),
      JSON.stringify({ version: "12.0.0" }),
    );
    assert.throws(() => runtimeResources("auth", dir), /version/);
    assert.throws(() => runtimeResources("auth", join(dir, "missing")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the Functions fixture requires its recorded locked SDK versions", async () => {
  const { mkdtempSync, mkdirSync, rmSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { runtimeResources } = await import("./rtdb-release-replay.mjs");
  const dir = mkdtempSync(join(tmpdir(), "rtdb-functions-"));
  try {
    for (const [name, version] of [
      ["firebase-functions", "7.3.2"],
      ["firebase-admin", "14.3.0"],
    ]) {
      mkdirSync(join(dir, "node_modules", name), { recursive: true });
      writeFileSync(join(dir, "node_modules", name, "package.json"), JSON.stringify({ version }));
    }
    for (const file of ["package-lock.json", "index.js", "frames.js"])
      writeFileSync(join(dir, file), file);
    assert.match(runtimeResources("functions", dir)["index.js"], /^[a-f0-9]{64}$/);
    writeFileSync(
      join(dir, "node_modules", "firebase-functions", "package.json"),
      '{"version":"0.0.0"}',
    );
    assert.throws(() => runtimeResources("functions", dir), /version/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("every RTDB campaign binds its recorded fixture and local producer sources", async () => {
  const { sourceResources } = await import("./rtdb-release-replay.mjs");
  for (const name of ["rest", "ondisconnect", "auth", "residual", "s5", "functions", "smoke"]) {
    const resources = sourceResources(name);
    assert.ok(Object.keys(resources).length >= 2, name);
    assert.ok(
      Object.values(resources).every((hash) => /^[a-f0-9]{64}$/.test(hash)),
      name,
    );
  }
  assert.throws(() => sourceResources("unknown"));
});

test(
  "the real local entrypoint binds the executed binary and refuses producer failure or binary changes",
  {
    skip:
      !existsSync(
        new URL(
          "../../tools/sdk-smoke-database/node_modules/firebase/package.json",
          import.meta.url,
        ),
      ) && "the release job installs the locked SDK dependencies",
  },
  async () => {
    const { mkdtempSync, chmodSync, rmSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { spawnSync } = await import("node:child_process");
    const dir = mkdtempSync(join(tmpdir(), "rtdb-exec-"));
    const binary = join(dir, "binary");
    const script = fileURLToPath(new URL("./rtdb-release-replay.mjs", import.meta.url));
    try {
      for (const [mode, body, expected] of [
        ["ok", "", 0],
        ["fail", "process.exit(7)", 2],
        ["changed", "require('node:fs').appendFileSync(process.argv[1], ' ')", 2],
      ]) {
        writeFileSync(binary, `#!${process.execPath}\n${body}\n`);
        chmodSync(binary, 0o700);
        const output = join(dir, `${mode}.json`);
        const result = spawnSync(
          process.execPath,
          [
            script,
            "local",
            "smoke",
            "--fireemu",
            binary,
            "--out",
            join(dir, mode),
            "--export",
            output,
          ],
          { encoding: "utf8", timeout: 5000 },
        );
        assert.equal(result.status, expected, result.stderr);
        assert.equal(existsSync(output), expected === 0, mode);
        if (expected === 0) assert.equal(JSON.parse(readFileSync(output)).match, true);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test("REST exports reject altered local bytes and a substituted historical fixture", () => {
  const expected = JSON.parse(
    readFileSync(
      new URL(
        "../../spec/compatibility/closure/evidence/RTDB-rest-comparison.json",
        import.meta.url,
      ),
    ),
  );
  const current = JSON.parse(
    readFileSync(
      new URL(
        "../../spec/compatibility/closure/evidence/RTDB-rest-v033-comparison.json",
        import.meta.url,
      ),
    ),
  );
  const hash = "a".repeat(64);
  const observed = { campaign: "rest", binarySha256: hash, match: true, result: current };
  assert.deepEqual(judgeExport("rest-old", observed, hash, expected), []);
  const changed = structuredClone(observed);
  changed.result.rows[0].local = { status: 599, bodyText: "corrupt local content", etag: "wrong" };
  assert.notDeepEqual(judgeExport("rest-old", changed, hash, expected), []);
  const alteredM14 = structuredClone(observed);
  alteredM14.result.m14[0].local.bodyText = "corrupt";
  assert.notDeepEqual(judgeExport("rest-old", alteredM14, hash, expected), []);
  const wrongSummary = structuredClone(expected);
  wrongSummary.summary.verdicts.MATCH = 121;
  assert.notDeepEqual(judgeExport("rest-old", observed, hash, wrongSummary), []);
  const wrongHistory = structuredClone(expected);
  wrongHistory.rows[0].verdict = "KNOWN_DIFFERENCE";
  assert.notDeepEqual(judgeExport("rest-old", observed, hash, wrongHistory), []);
  const wrongCurrent = structuredClone(current);
  wrongCurrent.rows[0].id = "other";
  assert.notDeepEqual(judgeExport("rest-v033", observed, hash, wrongCurrent), []);
  const wrongFixture = structuredClone(expected);
  wrongFixture.fixture.sha256 = "b".repeat(64);
  assert.notDeepEqual(judgeExport("rest-old", observed, hash, wrongFixture), []);
  assert.notDeepEqual(judgeExport("rest-v033", observed, hash, expected), []);
});
