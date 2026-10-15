// FS-8: the bad-path corpus (Rules get()/exists() on a path that is not a document of this
// database). The corpus is data; these tests pin its shape, the way it is selected and recorded,
// and what the recorder keeps when production answers either way. The facts the fake production
// uses are the test's choice, not claims about production.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { createContext, SANDBOX_PROJECT } from "./fs-rules/harness.mjs";
import {
  BAD_PATH_CASES,
  BAD_PATH_PROGRAMS,
  BAD_PATH_RULESET_IDS,
  corpusDigest,
  countRequests,
  markerOf,
  PRINCIPALS,
  PROGRAMS,
  programDigest,
  RULESET_TEXT,
  rulesetSource,
  validateCorpus,
} from "./fs-rules-v1/corpus.mjs";
import {
  brief,
  ceilings,
  classify,
  compareRows,
  fixtureText,
  selectPrograms,
  taskIdFor,
  TASK_ID,
  TASK_ID_BAD_PATH,
} from "./fs-rules-v1/judge.mjs";
import { preflight } from "./fs-rules-v1/preflight.mjs";
import { recordProduction } from "./fs-rules-v1/record.mjs";
import { runCorpus } from "./fs-rules-v1/session.mjs";
import { createClock, createWorld } from "./fs-rules-v1/test-world.mjs";

const PRODUCTION = {
  kind: "production",
  adminToken: "ya29.owner-test-token",
  apiKey: "AIzaFs8TestKeyNotReal",
  quotaProject: SANDBOX_PROJECT,
  projectNumber: "555500000001",
};

async function record({ scenario, programs = BAD_PATH_PROGRAMS } = {}) {
  const { world, fetchImpl, grpc } = createWorld(scenario);
  const clock = createClock();
  const ctx = createContext({ run: "1790000000000", startedMs: clock.now(), target: PRODUCTION });
  const out = await runCorpus(
    { programs, principals: PRINCIPALS },
    ctx,
    { fetchImpl, grpc, sleep: clock.sleep, now: clock.now },
    ceilings(programs),
  );
  return { out, world };
}

const rowsOf = (program) => program.steps.filter((step) => !step.publish);
const byRuleset = (id) => BAD_PATH_PROGRAMS.find((p) => p.ruleset === id);
const statusOf = (out, ruleset, row) => out.results[byRuleset(ruleset).id].steps[row].status;

// ---- the corpus -----------------------------------------------------------------------------

test("the bad-path corpus is four programs of reads, valid and bounded", () => {
  assert.deepEqual(
    BAD_PATH_PROGRAMS.map((p) => p.id),
    [
      "fs-rules-v1/bad-path/core",
      "fs-rules-v1/bad-path/other-database",
      "fs-rules-v1/bad-path/default-literal",
      "fs-rules-v1/bad-path/no-documents",
    ],
  );
  assert.deepEqual(BAD_PATH_RULESET_IDS, [
    "bad-path-core",
    "bad-path-other-database",
    "bad-path-default-literal",
    "bad-path-no-documents",
  ]);
  assert.equal(validateCorpus(BAD_PATH_PROGRAMS), 18);
  assert.equal(countRequests(BAD_PATH_PROGRAMS), 18);
  for (const program of BAD_PATH_PROGRAMS) {
    assert.deepEqual(program.steps[0], { id: "publishes", publish: true });
    for (const step of rowsOf(program)) {
      assert.equal(step.rpc, "get", `${step.id}: a plain REST get`);
      assert.equal(step.as, "none", `${step.id}: no credential`);
      assert.equal(step.transport, undefined, `${step.id}: REST only`);
      assert.match(step.doc, /^fsr8-[a-z0-9-]+\/[a-z]+$/);
    }
  }
});

test("each case has its own collection and its own allow get rule, over one seeded control document", () => {
  const ids = BAD_PATH_CASES.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const program of BAD_PATH_PROGRAMS) {
    assert.deepEqual(program.seed, [
      { doc: "fsr8-ctl/real", fields: { n: { integerValue: "1" } } },
    ]);
    const source = rulesetSource(program.ruleset);
    assert.ok(source.startsWith("rules_version = '2';\n"), program.ruleset);
    assert.ok(source.includes(`label == '${markerOf(program.ruleset)}'`));
    for (const step of rowsOf(program)) {
      const rule = BAD_PATH_CASES.find((c) => c.id === step.id);
      assert.ok(rule, `${step.id} is a case`);
      assert.ok(
        source.includes(
          `    match /fsr8-${rule.id}/{id} {\n      allow get: if ${rule.expr};\n    }`,
        ),
        `${step.id} has its rule`,
      );
      assert.equal(step.doc, `fsr8-${rule.id}/${rule.docId ?? "x"}`);
    }
  }
});

test("the cases cover collection paths, another database, the (default) literal and no /documents, with controls", () => {
  const exprs = Object.fromEntries(BAD_PATH_CASES.map((c) => [c.id, c.expr]));
  const documents = "/databases/$(database)/documents";
  // Controls: a real document, a missing document, a negated real document, a dynamic good path.
  assert.equal(exprs["ctl-exists-real"], `exists(${documents}/fsr8-ctl/real)`);
  assert.equal(exprs["ctl-missing-not-exists"], `!exists(${documents}/fsr8-ctl/absent)`);
  assert.equal(exprs["ctl-real-not-exists"], `!exists(${documents}/fsr8-ctl/real)`);
  assert.equal(exprs["ctl-missing-get-null"], `get(${documents}/fsr8-ctl/absent) == null`);
  assert.equal(exprs["dyn-doc-exists"], `exists(${documents}/fsr8-ctl/$(id))`);
  // The finding: a collection path, plain and negated, with get() compared to null, and a
  // collection path that is built from the request.
  assert.equal(exprs["coll-exists"], `exists(${documents}/fsr8-ctl)`);
  assert.equal(exprs["coll-not-exists"], `!exists(${documents}/fsr8-ctl)`);
  assert.equal(exprs["coll-get-null"], `get(${documents}/fsr8-ctl) == null`);
  assert.equal(exprs["nested-coll-not-exists"], `!exists(${documents}/fsr8-ctl/real/sub)`);
  assert.equal(exprs["dyn-coll-not-exists"], `!exists(${documents}/$(id))`);
  // Another database, the (default) literal, and a path with no /documents segment.
  assert.equal(exprs["other-not-exists"], "!exists(/databases/other/documents/fsr8-ctl/real)");
  assert.equal(exprs["other-get-null"], "get(/databases/other/documents/fsr8-ctl/real) == null");
  assert.equal(
    exprs["default-literal-exists"],
    "exists(/databases/(default)/documents/fsr8-ctl/real)",
  );
  assert.equal(exprs["nodocs-not-exists"], "!exists(/databases/$(database)/fsr8-ctl/real)");
  assert.equal(exprs["other-exists"], "exists(/databases/other/documents/fsr8-ctl/real)");
  assert.equal(
    exprs["default-literal-missing-not-exists"],
    "!exists(/databases/(default)/documents/fsr8-ctl/absent)",
  );
  assert.equal(exprs["nodocs-exists"], "exists(/databases/$(database)/fsr8-ctl/real)");
  assert.equal(exprs["nodocs-get-null"], "get(/databases/$(database)/fsr8-ctl/real) == null");
  assert.equal(BAD_PATH_CASES.length, 18);
});

test("a ruleset whose compile is uncertain is alone in its program", () => {
  // A ruleset production refuses to compile is recorded as such and takes every row of its
  // program with it, so the paths whose syntax is uncertain never share a ruleset with the core.
  const core = byRuleset("bad-path-core");
  const sources = rowsOf(core).map((s) => s.id);
  assert.ok(!sources.some((id) => /^(other|default-literal|nodocs)/.test(id)));
  for (const id of BAD_PATH_RULESET_IDS.filter((r) => r !== "bad-path-core")) {
    const ids = rowsOf(byRuleset(id)).map((s) => s.id);
    assert.ok(ids.length > 0 && ids.length <= 3, id);
  }
});

test("program digests are per program, follow the program's own ruleset and leave FS-3 alone", () => {
  const digests = BAD_PATH_PROGRAMS.map(programDigest);
  assert.equal(new Set(digests).size, 4);
  assert.notEqual(corpusDigest(BAD_PATH_PROGRAMS), corpusDigest(PROGRAMS));
  // A ruleset change moves the digest of the program that publishes it, and only that one.
  const [core, ...others] = BAD_PATH_PROGRAMS;
  assert.notEqual(
    programDigest({ ...core, ruleset: "bad-path-no-documents" }),
    programDigest(core),
  );
  assert.equal(others.length, 3);
});

test("a program digest covers its JSON and the rulesets it can publish, as FS-3 recorded it", () => {
  const sha = (text) => createHash("sha256").update(text).digest("hex");
  // FS-3 programs: the JSON and every FS-3 ruleset, byte for byte what the FS-3 fixture holds.
  for (const program of PROGRAMS)
    assert.equal(programDigest(program), sha(`${JSON.stringify(program)}\n${RULESET_TEXT}`));
  // FS-8 programs: the JSON and the program's own ruleset source.
  for (const program of BAD_PATH_PROGRAMS)
    assert.equal(
      programDigest(program),
      sha(`${JSON.stringify(program)}\n${rulesetSource(program.ruleset)}`),
    );
});

test("the corpus names no sandbox, address, number or absolute path", () => {
  const text =
    JSON.stringify(BAD_PATH_PROGRAMS) + BAD_PATH_RULESET_IDS.map(rulesetSource).join("\n");
  assert.ok(!/fireemu-oracle|fireemu-35fe6|@|\d{9,}|\/Users\/|\/home\//.test(text));
});

test("validateCorpus accepts a bad-path ruleset id and still refuses an unknown one", () => {
  const programs = structuredClone(BAD_PATH_PROGRAMS);
  assert.doesNotThrow(() => validateCorpus(programs));
  programs[0].ruleset = "bad-path-other";
  assert.throws(() => validateCorpus(programs), /unknown ruleset/);
});

// ---- selecting a corpus and naming the task -------------------------------------------------

test("FS3_CORPUS picks the family; the default stays FS-3", () => {
  assert.equal(selectPrograms(undefined, {}).length, 4);
  assert.deepEqual(
    selectPrograms(undefined, { FS3_CORPUS: "bad-path" }).map((p) => p.id),
    BAD_PATH_PROGRAMS.map((p) => p.id),
  );
  assert.equal(selectPrograms(undefined, { FS3_CORPUS: "v1" }).length, 4);
  assert.throws(() => selectPrograms(undefined, { FS3_CORPUS: "other" }), /FS3_CORPUS/);
  assert.deepEqual(
    selectPrograms(undefined, {
      FS3_CORPUS: "bad-path",
      FS3_PROGRAMS: "fs-rules-v1/bad-path/no-documents",
    }).map((p) => p.id),
    ["fs-rules-v1/bad-path/no-documents"],
  );
  // The prefix filter works inside the family chosen: an FS-3 prefix selects nothing here.
  assert.throws(
    () =>
      selectPrograms(undefined, {
        FS3_CORPUS: "bad-path",
        FS3_PROGRAMS: "fs-rules-v1/path-wildcard",
      }),
    /no program matches/,
  );
});

test("one run never mixes the two families", () => {
  assert.throws(() => selectPrograms([...PROGRAMS, ...BAD_PATH_PROGRAMS], {}), /mixes/);
});

test("the ledger task id follows the family", () => {
  assert.equal(TASK_ID, "FS-3-V1-RULES");
  assert.equal(TASK_ID_BAD_PATH, "FS-8-RULES-BAD-PATH");
  assert.equal(taskIdFor(PROGRAMS), TASK_ID);
  assert.equal(taskIdFor(BAD_PATH_PROGRAMS), TASK_ID_BAD_PATH);
  assert.equal(taskIdFor(BAD_PATH_PROGRAMS.slice(1, 2)), TASK_ID_BAD_PATH);
  assert.throws(() => taskIdFor([...PROGRAMS, ...BAD_PATH_PROGRAMS]), /mixes/);
  assert.throws(() => taskIdFor([]), /no program/);
});

// ---- a recording against the fake production ------------------------------------------------

test("a recording leaves the sandbox as it found it", async () => {
  const { out, world } = await record();
  assert.deepEqual(out.failures, []);
  assert.deepEqual(out.cleanupErrors, []);
  assert.equal(out.closureReady, true);
  assert.equal(out.requests, 18);
  assert.equal(world.releases.size + world.rulesets.size + world.accounts.size, 0);
  assert.equal(world.documents.size, 0);
  assert.deepEqual(
    Object.values(out.results).map((r) => r.steps.publishes),
    [{ compiled: true }, { compiled: true }, { compiled: true }, { compiled: true }],
  );
});

test("when production raises an evaluation error on a bad path, the rows say deny", async () => {
  const { out } = await record({ scenario: { badPath: "error" } });
  const s = (row, ruleset = "bad-path-core") => statusOf(out, ruleset, row);
  // Controls behave as documented in both worlds.
  assert.equal(s("ctl-exists-real"), 404, "allowed: the requested document is not there");
  assert.equal(s("ctl-missing-not-exists"), 404);
  assert.equal(s("ctl-real-not-exists"), 403);
  // A bad path raises: neither exists() nor !exists() allows.
  for (const row of ["coll-exists", "coll-not-exists", "coll-get-null", "nested-coll-not-exists"])
    assert.equal(s(row), 403, row);
  assert.equal(s("dyn-doc-exists"), 404);
  assert.equal(s("dyn-coll-not-exists"), 403);
  assert.equal(s("other-not-exists", "bad-path-other-database"), 403);
  assert.equal(s("other-get-null", "bad-path-other-database"), 403);
  assert.equal(s("nodocs-not-exists", "bad-path-no-documents"), 403);
  // The literal (default) database is this database.
  assert.equal(s("default-literal-exists", "bad-path-default-literal"), 404);
});

test("when production reads a bad path as missing, the rows say allow", async () => {
  const { out } = await record({ scenario: { badPath: "missing", getMissing: "null" } });
  const s = (row, ruleset = "bad-path-core") => statusOf(out, ruleset, row);
  assert.equal(s("coll-exists"), 403);
  assert.equal(s("coll-not-exists"), 404);
  assert.equal(s("coll-get-null"), 404);
  assert.equal(s("nested-coll-not-exists"), 404);
  assert.equal(s("dyn-coll-not-exists"), 404);
  assert.equal(s("other-not-exists", "bad-path-other-database"), 404);
  assert.equal(s("nodocs-not-exists", "bad-path-no-documents"), 404);
  assert.equal(s("ctl-missing-get-null"), 404);
});

test("the two worlds record different bodies, and the comparison tells them apart", async () => {
  const errorWorld = (await record({ scenario: { badPath: "error" } })).out;
  const missingWorld = (await record({ scenario: { badPath: "missing" } })).out;
  const harness = "h";
  const fixture = (out) => ({
    programs: Object.fromEntries(
      BAD_PATH_PROGRAMS.map((p) => [
        p.id,
        { corpusDigest: programDigest(p), harnessDigest: harness, steps: out.results[p.id].steps },
      ]),
    ),
  });
  const rows = compareRows({
    fixture: fixture(errorWorld),
    programs: BAD_PATH_PROGRAMS,
    local: missingWorld,
    harness,
  });
  const mismatched = new Set(rows.filter((r) => r.status === "MISMATCH").map((r) => r.row));
  assert.ok(mismatched.has("fs-rules-v1/bad-path/core#coll-not-exists"));
  assert.ok(mismatched.has("fs-rules-v1/bad-path/no-documents#nodocs-not-exists"));
  assert.ok(!mismatched.has("fs-rules-v1/bad-path/core#ctl-exists-real"));
  assert.ok(!mismatched.has("fs-rules-v1/bad-path/core#coll-exists"));
  const same = compareRows({
    fixture: fixture(errorWorld),
    programs: BAD_PATH_PROGRAMS,
    local: errorWorld,
    harness,
  });
  assert.ok(same.every((r) => r.status === "MATCH"));
  assert.equal(
    classify({ row: "x", production: undefined, fireemu: { status: 403 } }),
    "MISSING_FIXTURE",
  );
  assert.equal(
    brief(errorWorld.results[BAD_PATH_PROGRAMS[0].id].steps["coll-not-exists"]),
    "403 PERMISSION_DENIED",
  );
});

test("a ruleset production refuses to compile takes its rows with it and nothing else", async () => {
  const { out, world } = await record({
    scenario: {
      refuseSource: (content) => content.includes("/databases/$(database)/fsr8-ctl/real"),
    },
  });
  const program = byRuleset("bad-path-no-documents");
  const steps = out.results[program.id].steps;
  assert.deepEqual(steps.publishes, { compiled: false });
  for (const step of rowsOf(program))
    assert.deepEqual(steps[step.id], {
      status: -1,
      unresolved: "ruleset bad-path-no-documents did not compile",
    });
  assert.equal(statusOf(out, "bad-path-core", "ctl-exists-real"), 404);
  assert.deepEqual(out.failures, []);
  assert.equal(world.rulesets.size, 0, "every created ruleset is deleted");
});

test("the fixture keeps FS-3 programs and adds the bad-path ones", () => {
  const meta = { harness: "h", sha: "s", startedAt: "2026-10-15T00:00:00.000Z" };
  const row = { status: 403, body: [{ error: { status: "PERMISSION_DENIED" } }] };
  const recording = {
    results: Object.fromEntries(
      BAD_PATH_PROGRAMS.map((p) => [
        p.id,
        { steps: Object.fromEntries(p.steps.map((s) => [s.id, row])) },
      ]),
    ),
    diagnostics: {},
  };
  const existing = JSON.parse(
    fixtureText({
      programs: PROGRAMS,
      recordings: [
        {
          results: Object.fromEntries(
            PROGRAMS.map((p) => [p.id, { steps: { publishes: { compiled: true } } }]),
          ),
          diagnostics: {},
        },
        {
          results: Object.fromEntries(
            PROGRAMS.map((p) => [p.id, { steps: { publishes: { compiled: true } } }]),
          ),
          diagnostics: {},
        },
      ],
      meta,
    }),
  );
  const merged = JSON.parse(
    fixtureText({
      programs: BAD_PATH_PROGRAMS,
      recordings: [recording, recording],
      meta,
      existing,
    }),
  );
  assert.deepEqual(
    Object.keys(merged.programs),
    [...PROGRAMS.map((p) => p.id), ...BAD_PATH_PROGRAMS.map((p) => p.id)].toSorted((a, b) =>
      a.localeCompare(b),
    ),
  );
  assert.equal(countRequests(BAD_PATH_PROGRAMS), 18);
});

// ---- the production sequence for the FS-8 family --------------------------------------------

const NOW = Date.parse("2026-10-15T12:00:00Z");
const WEB = {
  apiKey: PRODUCTION.apiKey,
  projectNumber: "555500000001",
  projectId: SANDBOX_PROJECT,
};
const ENV = {
  FIREEMU_SANDBOX_LEDGER: "/ledger/sandbox.jsonl",
  FIREEMU_FS3_PRIVATE_DIR: "/private/fs8",
  FS3_NO_AUTH_RECORDING: new Date(NOW - 5 * 60_000).toISOString(),
  FS3_CORPUS: "bad-path",
};
const CLEAN = {
  failedReads: [],
  projectAccounts: 0,
  anonymousEnabled: true,
  rulesets: 0,
  otherLanesRecently: [],
  openRuns: [],
  releases: [],
  databases: ["(default)"],
  defaultHasDocuments: false,
};

function recordingOf(programs) {
  return {
    context: { run: "1", startedMs: 1 },
    results: Object.fromEntries(
      programs.map((p) => [
        p.id,
        {
          steps: Object.fromEntries(
            p.steps.map((s) => [
              s.id,
              s.publish
                ? { compiled: true }
                : { status: 403, body: { error: { status: "PERMISSION_DENIED" } } },
            ]),
          ),
        },
      ]),
    ),
    failures: [],
    cleanupErrors: [],
    publications: [],
    diagnostics: {},
    unknowns: [],
    closureReady: true,
    requests: 18,
    harnessRequests: 200,
  };
}

function deps(ledgerText = "") {
  const ledger = { text: ledgerText };
  const seen = { preflightTask: undefined, fixture: undefined };
  return {
    ledger,
    seen,
    deps: {
      now: () => NOW,
      readLedger: async () => ledger.text,
      appendLedger: async (_path, text) => {
        ledger.text += text;
      },
      assertCleanTree: async () => {},
      gitSha: async () => "a".repeat(40),
      harnessDigest: () => "h".repeat(64),
      assertIgnored: async () => {},
      makeRunDir: async () => {},
      writeRunFile: async () => {},
      clockOffset: async () => 0.01,
      sandboxWebConfig: async () => WEB,
      productionTarget: async () => PRODUCTION,
      preflight: async (_target, _ledger, taskId) => {
        seen.preflightTask = taskId;
        return { report: CLEAN, problems: [] };
      },
      recordOnce: async (programs) => recordingOf(programs),
      readFixture: async () => seen.fixture,
      writeFixture: async (text) => {
        seen.fixture = text;
      },
      scanFixture: async () => {},
      installSignals: async () => {},
      log: () => {},
      warn: () => {},
    },
  };
}

const ledgerLines = (ledger) =>
  ledger.text
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));

test("an FS-8 recording names its own task in both ledger lines and in the preflight", async () => {
  const fake = deps();
  const result = await recordProduction(ENV, fake.deps);
  assert.equal(result.outcome, "recorded");
  assert.deepEqual(
    ledgerLines(fake.ledger).map((l) => l.taskId),
    [TASK_ID_BAD_PATH, TASK_ID_BAD_PATH],
  );
  assert.equal(fake.seen.preflightTask, TASK_ID_BAD_PATH);
  const fixture = JSON.parse(fake.seen.fixture);
  assert.deepEqual(Object.keys(fixture.programs), BAD_PATH_PROGRAMS.map((p) => p.id).toSorted());
});

test("an FS-8 run is refused after an FS-8 abort but not after an FS-3 one", async () => {
  const abort = (taskId) =>
    `${JSON.stringify({
      ts: new Date(NOW - 20 * 60_000).toISOString(),
      project: SANDBOX_PROJECT,
      taskId,
      outcome: "aborted-fatal",
    })}\n`;
  await assert.rejects(
    recordProduction(ENV, deps(abort(TASK_ID_BAD_PATH)).deps),
    /the last run ended aborted-fatal/,
  );
  const other = deps(abort(TASK_ID));
  assert.equal((await recordProduction(ENV, other.deps)).outcome, "recorded");
});

test("the preflight counts FS-3's lines as another lane's, and its own as its own", async () => {
  const recent = (taskId) =>
    JSON.stringify({
      ts: new Date(NOW - 5 * 60_000).toISOString(),
      project: SANDBOX_PROJECT,
      taskId,
      event: "started",
    });
  const answers = async (url) => {
    const u = String(url);
    const body = u.includes("/releases")
      ? { releases: [] }
      : u.includes("/rulesets")
        ? {}
        : u.includes("/databases") && !u.includes(":runQuery")
          ? { databases: [{ name: `projects/${SANDBOX_PROJECT}/databases/(default)` }] }
          : u.includes(":runQuery")
            ? [{}]
            : u.includes("accounts:query")
              ? { recordsCount: "0" }
              : { signIn: { anonymous: { enabled: true } } };
    return { status: 200, json: async () => body };
  };
  const run = (taskId) =>
    preflight(PRODUCTION, `${recent(TASK_ID)}\n${recent(TASK_ID_BAD_PATH)}\n`, {
      now: NOW,
      fetchImpl: answers,
      taskId,
    });
  assert.deepEqual((await run(TASK_ID_BAD_PATH)).report.otherLanesRecently, [TASK_ID]);
  assert.deepEqual((await run(TASK_ID)).report.otherLanesRecently, [TASK_ID_BAD_PATH]);
});
