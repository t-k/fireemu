import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { runProduction } from "./auth-fs-cross/production.mjs";
import {
  ATB_AUTHORIZED_DOMAINS,
  ATB_TEST_PHONES,
  FOREIGN_PROJECT,
  SANDBOX_PROJECT,
  TASK_ID,
} from "./auth-fs-cross/sandbox.mjs";

const KEY = "AIzaSECRETKEYVALUE0123456789";
const NUMBER = "592603257417";

/** A fake production that answers the baseline reads, the compile probe and the foreign reads. */
function world(overrides = {}) {
  const state = {
    allowTenants: false,
    rulesets: [],
    foreignLeft: false,
    deleteThrows: false,
    compileStatus: 200,
    ...overrides,
  };
  const calls = [];
  const fetchJson = async (target, method, url, body, quota) => {
    calls.push({ method, url, quota });
    const path = new URL(url).pathname;
    if (path.endsWith("/config") && path.includes(FOREIGN_PROJECT))
      return { status: 200, json: { signIn: { email: { enabled: true } } } };
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
    if (method === "DELETE" && path.includes("/rulesets/")) {
      if (state.deleteThrows) throw new Error(`fetch failed with key ${KEY}`);
      state.rulesets = [];
      return { status: 200, json: {} };
    }
    if (path.endsWith("/databases"))
      return {
        status: 200,
        json: { databases: [{ name: `projects/${SANDBOX_PROJECT}/databases/(default)` }] },
      };
    if (path.endsWith("documents:runQuery")) return { status: 200, json: [{ readTime: "t" }] };
    if (path.endsWith("accounts:lookup"))
      return { status: 200, json: state.foreignLeft ? { users: [{ localId: "x" }] } : {} };
    throw new Error(`unrouted ${method} ${url}`);
  };
  return { state, calls, fetchJson };
}

const recording = (extra = {}) => ({
  requests: 89,
  harnessRequests: 300,
  foreignRequests: 5,
  failures: [],
  cleanupErrors: [],
  changes: ["tenant t1 created"],
  publications: [{}],
  timings: [{ step: "x", sinceDeletionMs: 65_100 }],
  foreignAccounts: [{ email: "afc-1-foreign@example.com", deleted: true }],
  ...extra,
});

function setup(t, { fake = world(), deps = {} } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "afc-production-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const ledger = join(dir, "sandbox-ledger.jsonl");
  writeFileSync(ledger, "");
  const run = () =>
    runProduction({
      ledger,
      privateRoot: join(dir, "private"),
      packetSha256: "p".repeat(64),
      programs: [{ id: "auth-fs-cross/x/y" }],
      operatorConfirmation: "2026-09-27T19:00:00.000Z",
      secrets: [
        [KEY, "api-key"],
        [NUMBER, "project-number"],
      ],
      admission: async () => ({
        sha: "s".repeat(40),
        harness: "h",
        problems: [],
        corpusDigest: "d",
      }),
      target: async () => ({ refresh: async () => {} }),
      fetchJson: fake.fetchJson,
      compileProbe: (fetchJson) =>
        import("./auth-fs-cross/production.mjs").then((m) => m.compileProbe(fetchJson)),
      clockOffset: async () => 0.01,
      recordOnce: async () => recording(),
      writeFixture: async () => ({}),
      recentAbort: () => undefined,
      now: () => new Date("2026-09-27T20:00:00Z"),
      log: () => {},
      ...deps,
    });
  const lines = () =>
    readFileSync(ledger, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l));
  return { dir, ledger, run, lines, lock: `${ledger}.lock`, fake };
}

test("a clean run writes both projects' lines and releases the lock", async (t) => {
  const { run, lines, lock } = setup(t);
  const result = await run();
  assert.equal(result.atBaseline, true);
  const rows = lines();
  assert.deepEqual(
    rows.map(({ event, project }) => [event, project]),
    [
      ["started", SANDBOX_PROJECT],
      ["started", FOREIGN_PROJECT],
      ["finished", SANDBOX_PROJECT],
      ["finished", FOREIGN_PROJECT],
    ],
  );
  assert.equal(rows[0].packetSha256, "p".repeat(64));
  assert.deepEqual(
    rows.slice(0, 2).map((r) => r.maxEstimatedUsd),
    [1, 0],
  );
  assert.ok(rows.slice(2).every((r) => r.outcome === "recorded" && r.sandboxAtBaseline === true));
  // idp: 2 recordings × (89 + 300 − 5) + 8 start reads + 3 compile probe + 8 final reads;
  // query: 2 × 5 + 1 start read + 1 config and 2 email lookups at the end.
  assert.equal(rows[2].requests, 2 * 384 + 8 + 3 + 8);
  assert.equal(rows[3].requests, 2 * 5 + 1 + 3);
  assert.equal(existsSync(lock), false);
});

test("a compile probe that fails after sending keeps the lock and asks for recovery", async (t) => {
  const { run, lines, lock } = setup(t, { fake: world({ deleteThrows: true }) });
  await assert.rejects(run(), /compile probe/);
  const rows = lines();
  assert.deepEqual(
    rows.map(({ event, reason }) => [event, reason]),
    [["needs-recovery", "compile-probe"]],
  );
  assert.doesNotMatch(JSON.stringify(rows), new RegExp(KEY));
  assert.equal(existsSync(lock), true);
});

test("a ruleset that does not compile stops before the started lines and releases the lock", async (t) => {
  const { run, lines, lock } = setup(t, { fake: world({ compileStatus: 400 }) });
  await assert.rejects(run(), /compile probe/);
  assert.deepEqual(lines(), []);
  assert.equal(existsSync(lock), false);
});

test("a sandbox off its baseline at the start stops before any write", async (t) => {
  const fake = world({ allowTenants: true });
  const { run, lines, lock } = setup(t, { fake });
  await assert.rejects(run(), /preflight: .*atb-2 allowTenants/);
  assert.deepEqual(lines(), []);
  assert.equal(existsSync(lock), false);
  assert.ok(
    fake.calls.every(
      ({ method, url }) => method === "GET" || /query|lookup|getIamPolicy|runQuery/.test(url),
    ),
  );
});

test("an account of the run left in the other project closes both projects as needs-recovery", async (t) => {
  const fake = world();
  const { run, lines, lock } = setup(t, {
    fake,
    deps: {
      recordOnce: async () => {
        fake.state.foreignLeft = true;
        return recording();
      },
    },
  });
  const result = await run();
  assert.equal(result.atBaseline, false);
  const closing = lines().slice(2);
  assert.deepEqual(
    closing.map(({ event, project }) => [event, project]),
    [
      ["needs-recovery", SANDBOX_PROJECT],
      ["needs-recovery", FOREIGN_PROJECT],
    ],
  );
  assert.match(closing[0].error, /a foreign account of the run remains/);
  assert.equal(existsSync(lock), true);
});

test("a fatal recording is read back, closed as needs-recovery when unclean, and scrubbed", async (t) => {
  const { run, lines, lock, dir } = setup(t, {
    deps: {
      recordOnce: async () => {
        throw Object.assign(new Error(`harness failed near ${KEY} (project ${NUMBER})`), {
          fatal: true,
          partial: recording({ cleanupErrors: ["tenant t1 is still listed"] }),
        });
      },
    },
  });
  await assert.rejects(
    run(),
    (error) => !error.message.includes(KEY) && /<api-key>/.test(error.message),
  );
  const closing = lines().slice(2);
  assert.ok(closing.every(({ event }) => event === "needs-recovery"));
  assert.doesNotMatch(
    readFileSync(join(dir, "sandbox-ledger.jsonl"), "utf8"),
    new RegExp(`${KEY}|${NUMBER}`),
  );
  const runDir = join(dir, "private", readdirSync(join(dir, "private"))[0]);
  assert.doesNotMatch(
    readFileSync(join(runDir, "meta.json"), "utf8"),
    new RegExp(`${KEY}|${NUMBER}`),
  );
  assert.equal(existsSync(lock), true);
});

test("program failures at baseline are also said as cleanup-verified, and other lanes accept the end", async (t) => {
  const { run, lines, lock } = setup(t, {
    deps: { recordOnce: async () => recording({ failures: [{ program: "p", error: "e" }] }) },
  });
  await run();
  const rows = lines();
  assert.deepEqual(
    rows.slice(2).map(({ event }) => event),
    ["finished", "finished", "cleanup-verified", "cleanup-verified"],
  );
  assert.equal(existsSync(lock), false);
  // AUTH-TENANT-BLOCKING's rule (conformance/src/auth-tenant-blocking/run.mjs, isCleanTerminal).
  const atbClean = (row) => {
    if (row.event === "started") return false;
    if (row.event === "cleanup-verified") return row.outcome === undefined;
    if (
      row.event !== undefined &&
      row.event !== "finished" &&
      row.event !== "campaign-control-terminal"
    )
      return false;
    if (row.sandboxAtBaseline === false) return false;
    if (row.outcome === "recorded" || row.outcome === "restored-by-hand") return true;
    return row.outcome?.startsWith("exploration") === true;
  };
  for (const project of [SANDBOX_PROJECT, FOREIGN_PROJECT]) {
    const last = rows.findLast((row) => row.project === project && row.taskId === TASK_ID);
    assert.equal(atbClean(last), true, project);
  }
});

test("admission problems stop the run before the lock", async (t) => {
  const { run, lock, lines } = setup(t, {
    deps: {
      admission: async () => ({ sha: "s", harness: "h", problems: ["the shared lock is held"] }),
    },
  });
  await assert.rejects(run(), /admission: the shared lock is held/);
  assert.equal(existsSync(lock), false);
  assert.deepEqual(lines(), []);
});

test("an empty list answered as {} reads as empty, and a failed read is a mismatch", async () => {
  const { readBaseline } = await import("./auth-fs-cross/production.mjs");
  const fake = world();
  const empty = async (target, method, url, body, quota) =>
    new URL(url).pathname.endsWith("/tenants")
      ? { status: 200, json: {} }
      : fake.fetchJson(target, method, url, body, quota);
  assert.deepEqual((await readBaseline((m, u, b, q) => empty({}, m, u, b, q))).mismatches, []);
  const failing = async (target, method, url, body, quota) =>
    new URL(url).pathname.endsWith("/releases")
      ? { status: 503, json: {} }
      : fake.fetchJson(target, method, url, body, quota);
  assert.deepEqual((await readBaseline((m, u, b, q) => failing({}, m, u, b, q))).mismatches, [
    "readback failed: releases (HTTP 503)",
  ]);
});

test("an approval already used by an earlier run is refused under the lock", async (t) => {
  const { run, ledger, lock } = setup(t);
  const earlier = [SANDBOX_PROJECT, FOREIGN_PROJECT].flatMap((project) => [
    {
      ts: "2026-09-27T10:00:00Z",
      event: "started",
      taskId: TASK_ID,
      project,
      packetSha256: "p".repeat(64),
    },
    {
      ts: "2026-09-27T10:30:00Z",
      event: "finished",
      taskId: TASK_ID,
      project,
      outcome: "recorded",
      sandboxAtBaseline: true,
    },
  ]);
  writeFileSync(ledger, `${earlier.map((row) => JSON.stringify(row)).join("\n")}\n`);
  await assert.rejects(run(), /approval was already used/);
  assert.equal(existsSync(lock), false);
});
