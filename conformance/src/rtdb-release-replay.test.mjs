import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { campaignPlan, judgeExport } from "./rtdb-release-replay.mjs";

const paths = [
  "rest-old",
  "ondisconnect",
  "auth",
  "residual",
  "s5",
  "sdk-small",
  "sdk-events",
  "sdk-rest",
  "sdk-rules",
  "sdk-tokens",
  "sdk-rules-load",
  "sdk-rules-syntax",
  "breadth",
  "kinds",
  "functions",
  "rest-v033",
];
test("each comparison resolves to its actual local producer and installed binary", () => {
  for (const name of paths) {
    const plan = campaignPlan(name, "/installed/fireemu", "/output");
    assert.ok(plan, name);
    assert.ok(plan.argv.includes("/installed/fireemu"), name);
    assert.ok(plan.argv[1].startsWith(fileURLToPath(new URL("../../", import.meta.url))), name);
    assert.ok(
      plan.argv.includes("local") || ["functions", "breadth", "kinds"].includes(name),
      name,
    );
  }
  assert.equal(campaignPlan("unknown", "/installed/fireemu", "/output"), undefined);
  for (const name of ["toString", "__proto__", "constructor"])
    assert.equal(campaignPlan(name, "/installed/fireemu", "/output"), undefined);
  assert.deepEqual(
    campaignPlan("rest-old", "/installed/fireemu", "/output"),
    campaignPlan("rest-v033", "/installed/fireemu", "/output"),
  );
});
test("campaign plans preserve caller-supplied binary and output paths", () => {
  for (let i = 0; i < 128; i++) {
    const binary = `relative binary ${i}`;
    const output = `relative output ${i}`;
    const plan = campaignPlan("rest-v033", binary, output);
    assert.equal(plan.argv[plan.argv.indexOf("--fireemu") + 1], binary);
    assert.equal(plan.argv[plan.argv.indexOf("--out") + 1], output);
  }
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
    fileURLToPath(new URL("../../tools/sdk-smoke-database/run.mjs", import.meta.url)),
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
    "sdk-small": "rtdb-sdk-small.mjs",
    "sdk-events": "rtdb-sdk-events.mjs",
    "sdk-rest": "rtdb-sdk-rest.mjs",
    "sdk-rules": "rtdb-sdk-rules.mjs",
    "sdk-tokens": "rtdb-sdk-tokens.mjs",
    "sdk-rules-load": "rtdb-sdk-rules-load.mjs",
    "sdk-rules-syntax": "rtdb-sdk-rules-syntax.mjs",
    breadth: "breadth-local-run.mjs",
    kinds: "kinds-replay-run.mjs",
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
      ["sdk-small", "production-sdk-small.json"],
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
  for (const name of [
    "rest",
    "ondisconnect",
    "auth",
    "residual",
    "s5",
    "sdk-small",
    "sdk-events",
    "sdk-rest",
    "sdk-rules",
    "sdk-tokens",
    "sdk-rules-load",
    "sdk-rules-syntax",
    "breadth",
    "kinds",
    "functions",
    "smoke",
  ]) {
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
        ["ok", "require('node:fs').writeFileSync(process.env.RTDB_TEST_CWD, process.cwd())", 0],
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
            "./binary",
            "--out",
            mode,
            "--export",
            `${mode}.json`,
          ],
          {
            encoding: "utf8",
            timeout: 5000,
            cwd: dir,
            env: { ...process.env, RTDB_TEST_CWD: join(dir, "cwd") },
          },
        );
        assert.equal(result.status, expected, result.stderr);
        assert.equal(existsSync(output), expected === 0, mode);
        if (expected === 0) {
          assert.equal(JSON.parse(readFileSync(output)).match, true);
          assert.equal(
            readFileSync(join(dir, "cwd"), "utf8"),
            fileURLToPath(new URL("../../", import.meta.url)).replace(/\/$/, ""),
          );
        }
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

test("the CI probe executable is readable by the artifact uploader", async () => {
  const { mkdtempSync, rmSync, statSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { createProbeExecutable } = await import("./rtdb-namespace-probe.mjs");
  const dir = mkdtempSync(join(tmpdir(), "rtdb-probe-mode-"));
  try {
    const binary = join(dir, "node");
    createProbeExecutable(binary);
    assert.equal(statSync(binary).mode & 0o777, 0o755);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the namespace probe refuses signals without the full owned process identity", async () => {
  const { sameOwnedIdentity } = await import("./rtdb-namespace-probe.mjs");
  const original = {
    pid: 23,
    birth: "45",
    comm: "unshare",
    args: "unshare --pid probe",
    exe: "/usr/bin/unshare",
  };
  assert.equal(sameOwnedIdentity(original, structuredClone(original)), true);
  for (const key of Object.keys(original))
    assert.equal(sameOwnedIdentity(original, { ...original, [key]: "different" }), false, key);
  assert.equal(sameOwnedIdentity(original, undefined), false);
});

test("the probe requires matching inherited pipe identities", async () => {
  const { sameInheritedPipe } = await import("./rtdb-namespace-probe.mjs");
  assert.equal(sameInheritedPipe("pipe:[123]", "pipe:[123]"), true);
  assert.equal(sameInheritedPipe("socket:[123]", "socket:[123]"), true);
  for (const [a, b] of [
    ["pipe:[123]", "pipe:[456]"],
    ["socket:[123]", "socket:[456]"],
    ["pipe:[123]", "socket:[123]"],
    ["/dev/null", "/dev/null"],
    [undefined, undefined],
  ])
    assert.equal(sameInheritedPipe(a, b), false);
});

test(
  "actual Node stderr inheritance uses the same anonymous stream",
  { skip: process.platform !== "linux" },
  async () => {
    const { spawn, spawnSync } = await import("node:child_process");
    const { sameInheritedPipe } = await import("./rtdb-namespace-probe.mjs");
    const code = `const {spawn}=require('node:child_process'); const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)','rtdb-stdio-owned'],{detached:true,stdio:['ignore','ignore','inherit']}); console.log(child.pid); setInterval(()=>{},1000);`;
    const parent = spawn(process.execPath, ["-e", code], { stdio: ["ignore", "pipe", "pipe"] });
    let pid, identity;
    try {
      const data = await Promise.race([
        new Promise((resolve) => parent.stdout.once("data", resolve)),
        new Promise((_, reject) => setTimeout(() => reject(Error("child startup timeout")), 3000)),
      ]);
      pid = Number(String(data).trim());
      identity = spawnSync(
        "/bin/ps",
        ["-p", String(pid), "-o", "lstart=", "-o", "comm=", "-o", "args="],
        { encoding: "utf8" },
      ).stdout;
      assert.match(identity, /rtdb-stdio-owned/);
      const { readlinkSync } = await import("node:fs");
      const parentFd = readlinkSync(`/proc/${parent.pid}/fd/2`);
      const childFd = readlinkSync(`/proc/${pid}/fd/2`);
      assert.equal(sameInheritedPipe(parentFd, childFd), true, `${parentFd} ${childFd}`);
    } finally {
      const status =
        pid &&
        spawnSync("/bin/ps", ["-p", String(pid), "-o", "lstart=", "-o", "comm=", "-o", "args="], {
          encoding: "utf8",
        }).stdout;
      if (identity && status === identity && status.includes("rtdb-stdio-owned")) {
        try {
          process.kill(pid, "SIGKILL");
        } catch {}
      }
      parent.kill("SIGKILL");
      parent.stdout.destroy();
      parent.stderr.destroy();
    }
  },
);

test(
  "generated descriptor combinations preserve the exact stream witness",
  { skip: !process.env.RTDB_DESCRIPTOR_ROWS },
  async () => {
    const { sameInheritedPipe } = await import("./rtdb-namespace-probe.mjs");
    const lines = readFileSync(process.env.RTDB_DESCRIPTOR_ROWS, "utf8")
      .trim()
      .split("\n")
      .slice(1);
    assert.equal(lines.length, 8);
    for (const line of lines) {
      const [kind, match, observed] = line.split("\t");
      const left =
        observed === "yes" ? (kind === "file" ? "/dev/null" : `${kind}:[123]`) : undefined;
      const right = match === "yes" ? left : `${kind}:[456]`;
      assert.equal(
        sameInheritedPipe(left, right),
        kind !== "file" && match === "yes" && observed === "yes",
        line,
      );
    }
  },
);

test("the SDK small campaign replays strict with the package SDK and binds the observer case code", async () => {
  const { sourceResources } = await import("./rtdb-release-replay.mjs");
  const plan = campaignPlan("sdk-small", "/installed/fireemu", "/output");
  assert.equal(plan.campaign, "sdk-small");
  assert.equal(plan.argv[plan.argv.indexOf("--profile") + 1], "strict");
  assert.ok(
    plan.argv[plan.argv.indexOf("--modules") + 1].endsWith(
      "/tools/sdk-smoke-database/node_modules",
    ),
  );
  const resources = Object.keys(sourceResources("sdk-small"));
  for (const file of [
    "rtdb-sdk-small.mjs",
    "rtdb-sdk-small-judge.mjs",
    "rtdb-sdk-small-fixture.mjs",
    "fixtures/production-sdk-small.json",
    ...[
      "actor.mjs",
      "sequence.mjs",
      "rules.mjs",
      "page.mjs",
      "page.html",
      "lib.mjs",
      "observer.mjs",
    ].map((name) => `sdk-observer/${name}`),
  ])
    assert.ok(resources.includes(`tools/sdk-smoke-database/${file}`), file);
  const hash = "b".repeat(64);
  assert.deepEqual(
    judgeExport("sdk-small", { campaign: "sdk-small", binarySha256: hash, match: true }, hash),
    [],
  );
  assert.equal(
    judgeExport("sdk-small", { campaign: "s5", binarySha256: hash, match: true }, hash).length,
    1,
  );
});

test("SDK small adjudication needs all 32 rows to match and refuses the v0.41.0 frozen clock", async () => {
  const { mkdtempSync, rmSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { adjudicate } = await import("./rtdb-release-replay.mjs");
  const fixture = JSON.parse(
    readFileSync(
      new URL("../../tools/sdk-smoke-database/fixtures/production-sdk-small.json", import.meta.url),
    ),
  );
  const dir = mkdtempSync(join(tmpdir(), "rtdb-sdk-small-"));
  try {
    writeFileSync(join(dir, "journal.json"), JSON.stringify(fixture));
    const good = adjudicate("sdk-small", dir);
    assert.equal(good.match, true);
    assert.equal(good.result.counts.MATCH, 32);
    for (const profile of fixture.profiles) {
      const st = profile.rows.find((row) => row.id === "server_timestamp").value;
      st.value = st.before - 300;
      profile.rows.find((row) => row.id === "increment").value.at = st.value;
    }
    writeFileSync(join(dir, "journal.json"), JSON.stringify(fixture));
    const frozen = adjudicate("sdk-small", dir);
    assert.equal(frozen.match, false);
    assert.deepEqual(frozen.result.counts, { MATCH: 24, MISMATCH: 8, NEEDS_REVIEW: 0 });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

const EVENTS_OBSERVER = [
  "events-actor.mjs",
  "events-sequence.mjs",
  "events-rules.mjs",
  "events-page.mjs",
  "events-page.html",
  "admin-suite.mjs",
  "lib.mjs",
  "observer.mjs",
  "actor.mjs",
  "sequence.mjs",
  "rules.mjs",
  "page.mjs",
  "page.html",
  "readback.mjs",
];

test("the SDK events campaign replays strict with the package SDKs and binds the fixture, judges and observer code", async () => {
  const { sourceResources, runtimeResources } = await import("./rtdb-release-replay.mjs");
  const plan = campaignPlan("sdk-events", "/installed/fireemu", "/output");
  assert.equal(plan.campaign, "sdk-events");
  assert.ok(plan.argv[1].endsWith("/tools/sdk-smoke-database/rtdb-sdk-events.mjs"));
  assert.deepEqual(plan.argv.slice(2, 7), [
    "local",
    "--fireemu",
    "/installed/fireemu",
    "--out",
    "/output",
  ]);
  assert.equal(plan.argv[plan.argv.indexOf("--profile") + 1], "strict");
  assert.equal(plan.argv.includes("--suite"), false, "the default suite is events+admin");
  assert.equal(
    plan.argv.includes("--against"),
    false,
    "the default recorded side is the committed fixture",
  );
  assert.ok(
    plan.argv[plan.argv.indexOf("--modules") + 1].endsWith(
      "/tools/sdk-smoke-database/node_modules",
    ),
  );
  const resources = Object.keys(sourceResources("sdk-events"));
  for (const file of [
    "rtdb-sdk-events.mjs",
    "rtdb-sdk-events-fixture.mjs",
    "rtdb-sdk-events-judge.mjs",
    "rtdb-sdk-admin-judge.mjs",
    "rtdb-sdk-small-fixture.mjs",
    "fixtures/production-sdk-events.json",
    ...EVENTS_OBSERVER.map((name) => `sdk-observer/${name}`),
  ])
    assert.ok(resources.includes(`tools/sdk-smoke-database/${file}`), file);
  // The pinned SDK packages are installed under tools/sdk-smoke-database only by the release job and on a
  // developer machine, not by the conformance workflow: the resources are read from a stand-in directory.
  const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const stand = mkdtempSync(join(tmpdir(), "rtdb-events-resources-"));
  let sdk;
  try {
    for (const [name, version] of [
      ["firebase", "12.18.0"],
      ["firebase-admin", "14.3.0"],
      ["playwright", "1.62.1"],
    ]) {
      mkdirSync(join(stand, "node_modules", name), { recursive: true });
      writeFileSync(join(stand, "node_modules", name, "package.json"), JSON.stringify({ version }));
    }
    for (const name of ["firebase-app.js", "firebase-auth.js", "firebase-database.js"])
      writeFileSync(join(stand, "node_modules", "firebase", name), name);
    writeFileSync(join(stand, "package-lock.json"), "{}");
    sdk = Object.keys(runtimeResources("sdk-events", stand));
  } finally {
    rmSync(stand, { recursive: true, force: true });
  }
  for (const file of [
    "package-lock.json",
    "node_modules/firebase/package.json",
    "node_modules/firebase-admin/package.json",
    "node_modules/playwright/package.json",
  ])
    assert.ok(sdk.includes(file), file);
  const hash = "c".repeat(64);
  assert.deepEqual(
    judgeExport("sdk-events", { campaign: "sdk-events", binarySha256: hash, match: true }, hash),
    [],
  );
  for (const observed of [
    { campaign: "sdk-small", binarySha256: hash, match: true },
    { campaign: "sdk-events", binarySha256: hash, match: false },
    { campaign: "sdk-events", binarySha256: "d".repeat(64), match: true },
  ])
    assert.equal(judgeExport("sdk-events", observed, hash).length, 1);
});

test("SDK events adjudication needs all 160 steps to match the committed fixture and refuses a fixture-shaped journal", async () => {
  const { mkdtempSync, rmSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { adjudicate } = await import("./rtdb-release-replay.mjs");
  const { recordedJournal } =
    await import("../../tools/sdk-smoke-database/rtdb-sdk-events-fixture.mjs");
  const fixture = JSON.parse(
    readFileSync(
      new URL(
        "../../tools/sdk-smoke-database/fixtures/production-sdk-events.json",
        import.meta.url,
      ),
    ),
  );
  const dir = mkdtempSync(join(tmpdir(), "rtdb-sdk-events-"));
  const run = (journal) => {
    writeFileSync(join(dir, "journal.json"), JSON.stringify(journal));
    return adjudicate("sdk-events", dir);
  };
  try {
    const local = recordedJournal(structuredClone(fixture));
    const good = run(local);
    assert.equal(good.match, true, JSON.stringify(good.result.problems));
    assert.equal(good.result.counts.MATCH, 160);
    assert.equal(run(fixture).match, false, "a local journal never carries a provenance");
    const reordered = structuredClone(local);
    const step = reordered.profiles[0].rows[3].steps.find((s) => s.observer.length > 1);
    step.observer.reverse();
    const one = run(reordered);
    assert.equal(one.match, false);
    assert.deepEqual(one.result.counts, { MATCH: 159, MISMATCH: 1, NEEDS_REVIEW: 0 });
    const admin = structuredClone(local);
    admin.profiles.pop();
    assert.equal(run(admin).match, false);
    const unsettled = structuredClone(local);
    unsettled.profiles[4].rows[1].steps[0].quiet = false;
    const bound = run(unsettled);
    assert.equal(bound.match, false);
    assert.equal(bound.result.counts.NEEDS_REVIEW, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the closure campaigns replay strict, judge the committed production reductions and refuse an altered local observation", async () => {
  const {
    adjudicate,
    campaignPlan: plan,
    runtimeResources,
  } = await import("./rtdb-release-replay.mjs");
  const { mkdtempSync, rmSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const fixtures = new URL("../../tools/sdk-smoke-database/fixtures/", import.meta.url);
  const read = (url) => JSON.parse(readFileSync(url, "utf8"));
  for (const name of [
    "sdk-rest",
    "sdk-rules",
    "sdk-tokens",
    "sdk-rules-load",
    "sdk-rules-syntax",
    "breadth",
    "kinds",
  ]) {
    const argv = plan(name, "/installed/fireemu", "/output").argv;
    assert.equal(
      argv.includes("local"),
      !["breadth", "kinds"].includes(name),
      `${name}: only the Functions producers have no local mode`,
    );
    assert.deepEqual(argv.slice(argv.indexOf("--fireemu")), [
      "--fireemu",
      "/installed/fireemu",
      "--out",
      "/output",
      "--profile",
      "strict",
    ]);
  }
  assert.deepEqual(runtimeResources("sdk-rest"), {});
  // The breadth fixture is its own directory (fixtures-breadth): installed, its handler source is bound; not installed, the error names it.
  try {
    const resources = runtimeResources("breadth");
    assert.ok(Object.hasOwn(resources, "node_modules/firebase-functions/package.json"));
    assert.equal(
      resources["index.js"],
      createHash("sha256")
        .update(
          readFileSync(new URL("./rtdb-functions/fixtures-breadth/index.js", import.meta.url)),
        )
        .digest("hex"),
    );
  } catch (error) {
    assert.match(String(error.message), /fixtures-breadth/);
  }
  // The kinds fixture is its own directory too (fixtures-kinds).
  try {
    const resources = runtimeResources("kinds");
    assert.ok(Object.hasOwn(resources, "node_modules/firebase-functions/package.json"));
    assert.equal(
      resources["index.js"],
      createHash("sha256")
        .update(readFileSync(new URL("./rtdb-functions/fixtures-kinds/index.js", import.meta.url)))
        .digest("hex"),
    );
  } catch (error) {
    assert.match(String(error.message), /fixtures-kinds/);
  }
  const { sourceResources } = await import("./rtdb-release-replay.mjs");
  for (const [name, suiteFile] of [
    ["sdk-rest", "rest-suite.mjs"],
    ["sdk-rules", "rules-suite.mjs"],
    ["sdk-tokens", "tokens-suite.mjs"],
    ["sdk-rules-load", "rules-load-suite.mjs"],
    ["sdk-rules-syntax", "rules-syntax-suite.mjs"],
  ]) {
    const keys = Object.keys(sourceResources(name));
    assert.ok(
      keys.some((key) => key.endsWith(`/sdk-observer/${suiteFile}`)),
      name,
    );
    assert.ok(
      keys.some((key) => key.endsWith(`/fixtures/production-${name}.json`)),
      name,
    );
  }
  assert.ok(
    Object.keys(sourceResources("breadth")).includes(
      "conformance/src/rtdb-functions/recorded/production-rtdb-breadth.json",
    ),
  );
  for (const source of [
    "kinds-replay-run.mjs",
    "kinds-replay.mjs",
    "kinds-local-run.mjs",
    "kinds-compare.mjs",
    "kinds-mask.mjs",
  ])
    assert.ok(
      Object.keys(sourceResources("kinds")).includes(`conformance/src/rtdb-functions/${source}`),
      source,
    );
  for (const recorded of ["production-rtdb-kinds.json", "production-rtdb-kinds-user-ladder.json"])
    assert.ok(
      Object.keys(sourceResources("kinds")).includes(
        `conformance/src/rtdb-functions/recorded/${recorded}`,
      ),
      recorded,
    );
  {
    // The kinds judge is wired in: a directory without the producer's runs is no match.
    const empty = mkdtempSync(join(tmpdir(), "rtdb-closure-kinds-"));
    try {
      assert.equal(adjudicate("kinds", empty).match, false);
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  }
  for (const name of ["rest", "rules", "tokens", "rules-load", "rules-syntax"]) {
    const dir = mkdtempSync(join(tmpdir(), `rtdb-closure-${name}-`));
    try {
      const strict = read(new URL(`closure-sdk-${name}-strict.json`, fixtures));
      writeFileSync(join(dir, "journal.json"), JSON.stringify(strict));
      const good = adjudicate(`sdk-${name}`, dir);
      assert.equal(good.match, true, name);
      strict.profiles[0].rows[0].status += 1;
      writeFileSync(join(dir, "journal.json"), JSON.stringify(strict));
      assert.equal(adjudicate(`sdk-${name}`, dir).match, false, name);
      // The emulator profile is not a strict production comparison: it does not satisfy the strict judge where it differs.
      if (name === "rest" || name === "tokens") {
        writeFileSync(
          join(dir, "journal.json"),
          readFileSync(new URL(`closure-sdk-${name}-emulator.json`, fixtures)),
        );
        assert.equal(adjudicate(`sdk-${name}`, dir).match, false, `${name} emulator`);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  const dir = mkdtempSync(join(tmpdir(), "rtdb-closure-breadth-"));
  try {
    const recorded = read(
      new URL("./rtdb-functions/recorded/local-strict-rtdb-breadth.json", import.meta.url),
    );
    const lines = recorded.frames.map(({ n: _n, step: _step, ...frame }) => JSON.stringify(frame));
    writeFileSync(join(dir, "frames.jsonl"), `${lines.join("\n")}\n`);
    assert.equal(adjudicate("breadth", dir).match, true);
    writeFileSync(join(dir, "frames.jsonl"), `${lines.slice(1).join("\n")}\n`);
    assert.equal(adjudicate("breadth", dir).match, false, "a missing delivery is a difference");
    // A delivery nothing explains is not matched even when every compared row still agrees.
    writeFileSync(
      join(dir, "frames.jsonl"),
      `${[...lines, JSON.stringify({ handler: "g9WrittenV2", generation: 2, event: { params: { group: "zz", id: "q" } }, attempt: { threw: false }, seq: 999, receivedAt: 0 })].join("\n")}\n`,
    );
    assert.equal(adjudicate("breadth", dir).match, false, "an unattributed local delivery");
    const emulator = read(
      new URL("./rtdb-functions/recorded/local-emulator-rtdb-breadth.json", import.meta.url),
    );
    writeFileSync(
      join(dir, "frames.jsonl"),
      `${emulator.frames.map(({ n: _n, step: _step, ...frame }) => JSON.stringify(frame)).join("\n")}\n`,
    );
    assert.equal(
      adjudicate("breadth", dir).match,
      false,
      "the emulator event shape is declared, not strict",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
