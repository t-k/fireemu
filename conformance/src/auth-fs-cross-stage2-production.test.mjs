import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { ATB_AUTHORIZED_DOMAINS, ATB_TEST_PHONES } from "./auth-fs-cross/sandbox.mjs";
import { runStage2Production } from "./auth-fs-cross/stage2-production.mjs";
import { SANDBOX_PROJECT, TASK_ID } from "./auth-fs-cross/stage2-sandbox.mjs";

const KEY = "AIzaSECRETKEYVALUE0123456789";
const PACKET = "a".repeat(64);
const COMMIT = "b".repeat(40);
const HARNESS = "c".repeat(64);
const RUNNER = { project: SANDBOX_PROJECT, maxRequests: 3_000, reserveUsd: 1 };
const pins = `packetSha256=${PACKET}; sourceCommit=${COMMIT}; harnessDigest=${HARNESS}`;
const ENVELOPE = `- 2026-09-29 | AUTH-FS-CROSS stage-2 packet envelope | envelopeId=AFC-S2-1; project=${SANDBOX_PROJECT}; maxRequests=3500; reserveUsd=1.5; writes=run-owned; iamConfig=none; retries=none | オーナー（Claude経由） | x\n- 2026-09-29 | AUTH-FS-CROSS stage-2 packet | decision=APPROVE; envelopeId=AFC-S2-1; ${pins} | Claude（委任。枠の内の承認し直し） | y\n`;

/** A fake production answering the baseline reads and the compile probe. */
function world(overrides = {}) {
  const state = {
    allowTenants: false,
    rulesets: [],
    compileStatus: 200,
    deleteThrows: false,
    keys: [
      {
        displayName: "Browser key (auto created by Firebase)",
        restrictions: { apiTargets: [{ service: "identitytoolkit.googleapis.com" }] },
      },
    ],
    ...overrides,
  };
  const calls = [];
  const fetchJson = async (target, method, url, body) => {
    calls.push({ method, url });
    const path = new URL(url).pathname;
    if (path.endsWith("/locations/global/keys")) return { status: 200, json: { keys: state.keys } };
    if (path.endsWith("/config"))
      return {
        status: 200,
        json: {
          multiTenant: { allowTenants: state.allowTenants },
          emailPrivacyConfig: { enableImprovedEmailPrivacy: true },
          client: { permissions: {} },
          signIn: {
            email: { enabled: true, passwordRequired: true },
            anonymous: { enabled: true },
            phoneNumber: { enabled: true, testPhoneNumbers: { ...ATB_TEST_PHONES } },
          },
          mfa: { state: "DISABLED" },
          authorizedDomains: ATB_AUTHORIZED_DOMAINS,
        },
      };
    if (path.endsWith("/tenants"))
      return { status: 400, json: { error: { message: "INVALID_PROJECT_ID" } } };
    if (path.endsWith("accounts:query")) return { status: 200, json: { recordsCount: "0" } };
    if (path.endsWith(":getIamPolicy")) return { status: 200, json: { bindings: [] } };
    if (path.endsWith("/releases")) return { status: 200, json: {} };
    if (path.endsWith("/rulesets") && method === "GET")
      return { status: 200, json: { rulesets: state.rulesets } };
    if (path.endsWith("/rulesets") && method === "POST") {
      if (state.compileStatus !== 200) return { status: state.compileStatus, json: {} };
      state.rulesets.push({ name: `projects/${SANDBOX_PROJECT}/rulesets/r1` });
      return { status: 200, json: { name: `projects/${SANDBOX_PROJECT}/rulesets/r1` } };
    }
    if (method === "DELETE") {
      if (state.deleteThrows) throw new Error("socket hang up");
      state.rulesets = [];
      return { status: 200, json: {} };
    }
    if (path.endsWith("/databases"))
      return {
        status: 200,
        json: { databases: [{ name: `projects/${SANDBOX_PROJECT}/databases/(default)` }] },
      };
    if (path.endsWith(":runQuery")) return { status: 200, json: [{ readTime: "t" }] };
    throw new Error(`unexpected ${method} ${url} ${body}`);
  };
  return { state, calls, fetchJson };
}

function setup({
  owner = ENVELOPE,
  ledger = "",
  recording = 1,
  window,
  worldOptions,
  runner = RUNNER,
} = {}) {
  const dir = mkdtempSync(join(tmpdir(), "afc2-production-"));
  const paths = {
    dir,
    ledger: join(dir, "sandbox-ledger.jsonl"),
    legacyLock: join(dir, "sandbox-ledger.jsonl.lock"),
    lockDir: join(dir, "sandbox-locks"),
    ownerDecisions: join(dir, "owner-decisions.md"),
    privateRoot: join(dir, "private"),
  };
  writeFileSync(paths.ledger, ledger);
  writeFileSync(paths.ownerDecisions, owner);
  const fake = world(worldOptions);
  let clock = Date.parse("2026-09-29T00:00:00Z");
  const deps = {
    ...paths,
    packetSha256: PACKET,
    recording,
    runner,
    secrets: [[KEY, "api-key"]],
    admission: async () => ({
      problems: [],
      sha: COMMIT,
      harness: HARNESS,
      programDigest: "p".repeat(64),
    }),
    target: async () => ({ refresh: async () => {} }),
    fetchJson: fake.fetchJson,
    clockOffset: async () => 0.01,
    browserKeyProbe: async () => ({ ok: true, code: null, requests: 2 }),
    compileProbe: undefined,
    recordWindow:
      window ??
      (async () => ({
        rows: { r: { note: `key ${KEY}` } },
        harnessRequests: 120,
        requests: 0,
        wire: { a: 30, b: 12 },
        cleanupErrors: [],
        changes: ["tenant t1 created"],
        publications: [{}],
      })),
    now: () => new Date((clock += 1_000)),
    recentAbort: () => false,
    stopRequested: () => false,
    log: () => {},
  };
  return { paths, deps, fake, done: () => rmSync(dir, { recursive: true, force: true }) };
}

const lines = (path) =>
  readFileSync(path, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
const withProbe = async (deps) => {
  const { compileProbe } = await import("./auth-fs-cross/stage2-production.mjs");
  return { ...deps, compileProbe };
};

test("an approved recording writes its lines, keeps its secrets out and releases its lock", async () => {
  const { paths, deps, fake, done } = setup();
  try {
    const result = await runStage2Production(await withProbe(deps));
    assert.equal(result.outcome, "recorded");
    assert.equal(result.atBaseline, true);
    const written = lines(paths.ledger);
    assert.deepEqual(
      written.map((l) => [l.event, l.stage, l.recording, l.project]),
      [
        ["started", 2, 1, SANDBOX_PROJECT],
        ["finished", 2, 1, SANDBOX_PROJECT],
      ],
    );
    assert.equal(written[0].approval, "envelope");
    assert.equal(written[0].envelopeId, "AFC-S2-1");
    assert.equal(written[0].maxEstimatedUsd, 1);
    // 8 baseline reads, 3 probe requests, 120 harness, 42 SDK, 8 final reads.
    // With the API keys read (1) and the key probe's requests (2).
    assert.equal(written[1].requests, 8 + 1 + 2 + 3 + 120 + 42 + 8);
    assert.equal(written[1].sdkRequests, 42);
    assert.equal(written[1].outcome, "recorded");
    assert.deepEqual(readdirSync(paths.lockDir), []);
    const [runDir] = readdirSync(paths.privateRoot);
    const saved = readFileSync(join(paths.privateRoot, runDir, "recording.json"), "utf8");
    assert.equal(saved.includes(KEY), false);
    assert.equal(statSync(join(paths.privateRoot, runDir, "recording.json")).mode & 0o777, 0o600);
    // Every production call named the sandbox project only.
    for (const { url } of fake.calls)
      for (const [, p] of url.matchAll(/projects\/([^/]+)/g)) assert.equal(p, SANDBOX_PROJECT);
  } finally {
    done();
  }
});

test("without an approval, or with the runner's project undeclared, nothing is taken or written", async () => {
  for (const options of [
    { owner: "" },
    { runner: { ...RUNNER, project: "fireemu-oracle-query" } },
    { runner: { ...RUNNER, maxRequests: 4_000 } },
  ]) {
    const { paths, deps, fake, done } = setup(options);
    try {
      await assert.rejects(
        runStage2Production(await withProbe(deps)),
        /approval|not the declared one/,
      );
      assert.equal(readFileSync(paths.ledger, "utf8"), "");
      assert.equal(existsSync(paths.lockDir), false);
      assert.deepEqual(fake.calls, []);
    } finally {
      done();
    }
  }
});

test("a held lock of the project, or the legacy lock, stops the run before any request", async () => {
  const held = setup();
  const legacy = setup();
  try {
    await (await import("node:fs/promises")).mkdir(held.paths.lockDir, { mode: 0o700 });
    writeFileSync(join(held.paths.lockDir, `${SANDBOX_PROJECT}.lock`), '{"taskId":"OTHER"}');
    await assert.rejects(runStage2Production(await withProbe(held.deps)), /is held/);
    assert.equal(
      readFileSync(join(held.paths.lockDir, `${SANDBOX_PROJECT}.lock`), "utf8"),
      '{"taskId":"OTHER"}',
    );
    writeFileSync(legacy.paths.legacyLock, "{}");
    await assert.rejects(runStage2Production(await withProbe(legacy.deps)), /legacy shared lock/);
    for (const { paths, fake } of [held, legacy]) {
      assert.equal(readFileSync(paths.ledger, "utf8"), "");
      assert.deepEqual(fake.calls, []);
    }
  } finally {
    held.done();
    legacy.done();
  }
});

test("recording 2 before recording 1 ended recorded is refused under the lock, which is released", async () => {
  const { paths, deps, fake, done } = setup({ recording: 2 });
  try {
    await assert.rejects(
      runStage2Production(await withProbe(deps)),
      /recording 1 of this packet did not end/,
    );
    assert.equal(readFileSync(paths.ledger, "utf8"), "");
    assert.deepEqual(readdirSync(paths.lockDir), []);
    assert.deepEqual(fake.calls, []);
  } finally {
    done();
  }
});

test("a failed window at baseline ends aborted and verified; off baseline it needs recovery and keeps the lock", async () => {
  const failing = async () => {
    throw Object.assign(new Error(`boom ${KEY}`), {
      partial: { rows: {}, wire: { a: 3 }, harnessRequests: 5, cleanupErrors: [] },
    });
  };
  const atBaseline = setup({ window: failing });
  const off = setup({ window: failing, worldOptions: {} });
  try {
    await assert.rejects(runStage2Production(await withProbe(atBaseline.deps)), (error) =>
      /boom <api-key>/.test(error.message),
    );
    assert.deepEqual(
      lines(atBaseline.paths.ledger).map((l) => [l.event, l.outcome ?? null]),
      [
        ["started", null],
        ["finished", "aborted"],
        ["cleanup-verified", null],
      ],
    );
    assert.deepEqual(readdirSync(atBaseline.paths.lockDir), []);
    const [runDir] = readdirSync(atBaseline.paths.privateRoot);
    assert.ok(existsSync(join(atBaseline.paths.privateRoot, runDir, "recording-partial.json")));

    // The window leaves multi-tenancy on: the final readback differs from the baseline.
    const leaving = async () => {
      off.fake.state.allowTenants = true;
      return failing();
    };
    off.deps.recordWindow = leaving;
    await assert.rejects(runStage2Production(await withProbe(off.deps)), /boom/);
    const written = lines(off.paths.ledger);
    assert.deepEqual(
      written.map((l) => l.event),
      ["started", "needs-recovery"],
    );
    assert.equal(written[1].sandboxAtBaseline, false);
    assert.match(written[1].error, /atb-2 allowTenants/);
    // The window's error is scrubbed before it reaches the ledger.
    assert.match(written[1].error, /boom <api-key>/);
    assert.equal(readFileSync(off.paths.ledger, "utf8").includes(KEY), false);
    assert.deepEqual(readdirSync(off.paths.lockDir), [`${SANDBOX_PROJECT}.lock`]);
  } finally {
    atBaseline.done();
    off.done();
  }
});

test("a compile probe that leaves a ruleset needs recovery; one that fails to compile cleanly does not", async () => {
  const leaves = setup({ worldOptions: { deleteThrows: true } });
  const refused = setup({ worldOptions: { compileStatus: 400 } });
  try {
    await assert.rejects(runStage2Production(await withProbe(leaves.deps)), /compile probe/);
    assert.deepEqual(
      lines(leaves.paths.ledger).map((l) => [l.event, l.reason]),
      [["needs-recovery", "compile-probe"]],
    );
    assert.deepEqual(readdirSync(leaves.paths.lockDir), [`${SANDBOX_PROJECT}.lock`]);
    await assert.rejects(runStage2Production(await withProbe(refused.deps)), /compile probe/);
    assert.equal(readFileSync(refused.paths.ledger, "utf8"), "");
    assert.deepEqual(readdirSync(refused.paths.lockDir), []);
  } finally {
    leaves.done();
    refused.done();
  }
});

test("another task's open run on the project stops the run under the lock", async () => {
  const other = JSON.stringify({
    ts: "2026-09-28T00:00:00Z",
    taskId: "OTHER",
    project: SANDBOX_PROJECT,
    event: "started",
  });
  const { paths, deps, fake, done } = setup({ ledger: `${other}\n` });
  try {
    await assert.rejects(
      runStage2Production(await withProbe(deps)),
      /OTHER on fireemu-oracle-idp is open/,
    );
    assert.deepEqual(readdirSync(paths.lockDir), []);
    assert.deepEqual(fake.calls, []);
    assert.equal(lines(paths.ledger).length, 1);
    assert.equal(lines(paths.ledger)[0].taskId, "OTHER");
    assert.equal(TASK_ID, "AUTH-FS-CROSS-SANDBOX");
  } finally {
    done();
  }
});

test("a key with an application restriction, or a refused key probe, stops the run before any write", async () => {
  const restricted = setup({
    worldOptions: {
      keys: [
        { displayName: "k", restrictions: { browserKeyRestrictions: { allowedReferrers: ["x"] } } },
      ],
    },
  });
  const refused = setup();
  refused.deps.browserKeyProbe = async () => ({
    ok: false,
    code: "auth/requests-from-referer-blocked",
    requests: 1,
  });
  try {
    await assert.rejects(
      runStage2Production(await withProbe(restricted.deps)),
      /API key k has an application restriction/,
    );
    await assert.rejects(
      runStage2Production(await withProbe(refused.deps)),
      /browser key probe refused: auth\/requests-from-referer-blocked/,
    );
    // Each stop is written down for the owner, naming the keys (never their strings) or the
    // probe's code; nothing was written to the sandbox, so it ends cleanly.
    const [keyStop] = lines(restricted.paths.ledger);
    assert.deepEqual(
      [
        keyStop.event,
        keyStop.outcome,
        keyStop.sandboxAtBaseline,
        keyStop.reason,
        keyStop.keys,
        keyStop.estimatedUsd,
      ],
      [
        "finished",
        "stopped-before-write",
        true,
        "api-key-application-restriction",
        [{ displayName: "k", uid: null }],
        0,
      ],
    );
    const [probeStop] = lines(refused.paths.ledger);
    assert.deepEqual(
      [probeStop.outcome, probeStop.reason, probeStop.code, probeStop.requests],
      [
        "stopped-before-write",
        "browser-key-probe-refused",
        "auth/requests-from-referer-blocked",
        8 + 1 + 1,
      ],
    );
    // The same recording may run again under the same approval: nothing started.
    const { admissionProblems } = await import("./auth-fs-cross/sandbox.mjs");
    const { recordingProblems } = await import("./auth-fs-cross/stage2-sandbox.mjs");
    const text = readFileSync(refused.paths.ledger, "utf8");
    assert.deepEqual(recordingProblems(text, PACKET, 1), []);
    assert.deepEqual(
      admissionProblems(text, SANDBOX_PROJECT, Date.parse("2026-09-29T02:00:00Z")),
      [],
    );
    for (const { paths, fake } of [restricted, refused]) {
      assert.equal(lines(paths.ledger).length, 1);
      assert.deepEqual(readdirSync(paths.lockDir), []);
      // Reads only: the baseline, the keys, nothing that writes.
      assert.deepEqual(
        fake.calls.filter(
          ({ method, url }) =>
            method !== "GET" &&
            !/(accounts:query|:getIamPolicy|:runQuery)$/.test(new URL(url).pathname),
        ),
        [],
      );
    }
  } finally {
    restricted.done();
    refused.done();
  }
});

test("a runner of an undeclared project stops even under an approval that covers it", async () => {
  const query = "fireemu-oracle-query";
  const owner = ENVELOPE.replace(`project=${SANDBOX_PROJECT}`, `project=${query}`);
  const { paths, deps, fake, done } = setup({ owner, runner: { ...RUNNER, project: query } });
  try {
    await assert.rejects(runStage2Production(await withProbe(deps)), /not the declared one/);
    assert.equal(readFileSync(paths.ledger, "utf8"), "");
    assert.deepEqual(fake.calls, []);
  } finally {
    done();
  }
});

test("a window whose own cleanup failed needs recovery and keeps the lock, even at baseline", async () => {
  const { paths, deps, done } = setup({
    window: async () => ({
      rows: {},
      wire: {},
      harnessRequests: 1,
      cleanupErrors: ["delete tenant t1: HTTP 500"],
    }),
  });
  try {
    await runStage2Production(await withProbe(deps));
    const written = lines(paths.ledger);
    assert.deepEqual(
      written.map((l) => l.event),
      ["started", "needs-recovery"],
    );
    assert.match(written[1].error, /delete tenant t1/);
    assert.deepEqual(readdirSync(paths.lockDir), [`${SANDBOX_PROJECT}.lock`]);
  } finally {
    done();
  }
});

test("recording 2 is admitted by recording 1's own closing line", async () => {
  const first = setup();
  try {
    await runStage2Production(await withProbe(first.deps));
    const ledgerAfterFirst = readFileSync(first.paths.ledger, "utf8");
    for (const line of lines(first.paths.ledger))
      assert.equal(line.packetSha256, PACKET, line.event);
    const second = setup({ ledger: ledgerAfterFirst, recording: 2 });
    try {
      const result = await runStage2Production(await withProbe(second.deps));
      assert.equal(result.outcome, "recorded");
      assert.deepEqual(
        lines(second.paths.ledger).map((l) => [l.event, l.recording]),
        [
          ["started", 1],
          ["finished", 1],
          ["started", 2],
          ["finished", 2],
        ],
      );
    } finally {
      second.done();
    }
  } finally {
    first.done();
  }
});

test("a stop requested before the first write writes nothing and releases the lock", async () => {
  const { paths, deps, fake, done } = setup();
  deps.stopRequested = () => true;
  try {
    await assert.rejects(
      runStage2Production(await withProbe(deps)),
      /stopped by a signal before any write/,
    );
    assert.equal(readFileSync(paths.ledger, "utf8"), "");
    assert.deepEqual(readdirSync(paths.lockDir), []);
    // Reads only: no ruleset was created.
    assert.equal(
      fake.calls.some(
        ({ method, url }) => method === "POST" && new URL(url).pathname.endsWith("/rulesets"),
      ),
      false,
    );
  } finally {
    done();
  }
});

test("multi-tenancy left on at the start stops the run before any write", async () => {
  const { paths, deps, fake, done } = setup({ worldOptions: { allowTenants: true } });
  try {
    await assert.rejects(
      runStage2Production(await withProbe(deps)),
      /preflight: .*atb-2 allowTenants/,
    );
    assert.equal(readFileSync(paths.ledger, "utf8"), "");
    assert.deepEqual(readdirSync(paths.lockDir), []);
    assert.equal(
      fake.calls.some(
        ({ method, url }) => method === "POST" && new URL(url).pathname.endsWith("/rulesets"),
      ),
      false,
    );
  } finally {
    done();
  }
});

test("the browser key probe fails on a refused request or a page error, not only on its result", async () => {
  const { browserKeyProbe } = await import("./auth-fs-cross/stage2-record.mjs");
  const fakeProbe =
    (events, result = { ok: true }) =>
    async () =>
      browserKeyProbe(
        { mode: "production", web: {} },
        {
          spawn: (config) => {
            assert.equal(config.wireCap, 5);
            return {
              events,
              ready: async () => ({}),
              send: async () => result,
              close: async () => {},
            };
          },
        },
      );
  assert.deepEqual(await fakeProbe([{ event: "wire", host: "h" }])(), {
    ok: true,
    code: null,
    requests: 1,
  });
  assert.deepEqual(await fakeProbe([], { ok: false, code: "auth/network-request-failed" })(), {
    ok: false,
    code: "auth/network-request-failed",
    requests: 0,
  });
  assert.deepEqual(await fakeProbe([{ event: "wire-refused", host: "x.example" }])(), {
    ok: false,
    code: "wire-refused:x.example",
    requests: 0,
  });
  assert.equal((await fakeProbe([{ event: "page-error", message: "m" }])()).code, "page-error");
});
