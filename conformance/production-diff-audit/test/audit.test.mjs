import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, rm, mkdir, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { fixtureSubject } from "./subject.mjs";
import {
  auditSubject,
  auditExitCode,
  canonical,
  fingerprint,
  buildProbes,
  syntheticControl,
  renderReport,
} from "../suite.mjs";
import { main, parseArgs } from "../audit.mjs";
import { loadInstalled } from "../installed.mjs";
const subject = await fixtureSubject();
const run = (s = subject) => auditSubject(s, s.identity);
const good = run();

function consistentVerdict(result, verdict) {
  result.verdict = verdict;
  result.rows = result.rows.map((row) => ({ ...row, comparison: verdict }));
  result.counts = { match: 0, mismatch: 0, indeterminate: 0 };
  result.counts[verdict.toLowerCase()] = result.rows.length;
  return result;
}

test("the real pilot comparator slice matches the reviewed SHA-256", () => {
  assert.equal(subject.identity.comparatorSliceSha256, subject.entry.comparatorSliceSha256);
});
test("the synthetic baseline is clearly not a production or native run", () => {
  assert.equal(good.auditPassed, true);
  assert.equal(good.identity.kind, "derived-test-fixture");
  assert.equal(good.identity.completeRepositoryValidation, false);
  assert.equal(good.baselineKind, "synthetic-local-control-from-saved-production-projection");
  for (const key of [
    "productionExecuted",
    "nativeRuntimeExecuted",
    "freshLocalExecution",
    "acquisitionValidated",
    "parentPromotion",
    "compatibilityEstablished",
  ])
    assert.equal(good[key], false);
});
test("summary separates 34 semantic from integrity/binding/envelope/tolerance probes", () => {
  assert.equal(good.outcomes.length, 75);
  assert.deepEqual(
    Object.fromEntries(Object.entries(good.summary.groups).map(([k, v]) => [k, v.total])),
    { semantic: 34, integrity: 26, binding: 3, envelope: 5, tolerance: 7 },
  );
  assert.equal(good.summary.semanticDetected, 34);
  assert.equal(good.summary.semanticMissed, 0);
});
for (const row of good.outcomes)
  test(`actual subject: ${row.id} -> ${row.expected}`, () => {
    assert.equal(row.mutationApplied, true);
    assert.equal(row.observed, row.expected);
    assert.equal(row.passed, true);
    assert.match(row.syntheticInputSha256, /^[a-f0-9]{64}$/);
  });
test("running twice yields deterministic probe IDs and fingerprints", () => {
  assert.deepEqual(run(), good);
  assert.equal(new Set(good.outcomes.map((r) => r.id)).size, good.outcomes.length);
});
test("the production projection and logical program are not modified", () => {
  const before = JSON.stringify({ program: subject.program, production: subject.production });
  run();
  assert.equal(
    JSON.stringify({ program: subject.program, production: subject.production }),
    before,
  );
});
test("outputs do not contain original response bodies or resource names", () => {
  const json = JSON.stringify(good);
  assert.ok(!json.includes("projects/demo-firestore-probe"));
  assert.ok(!json.includes("the same document cannot be written"));
  assert.ok(!json.includes('"production":{"'));
});
test("canonicalization keeps JSON types, null/absent, arrays and their order distinct", () => {
  for (const [a, b] of [
    [true, 1],
    ["1", 1],
    [{}, { a: null }],
    [
      [1, 2],
      [2, 1],
    ],
    [[], {}],
  ])
    assert.notEqual(fingerprint(a), fingerprint(b));
  assert.equal(canonical({ a: 1, b: 2 }), canonical({ b: 2, a: 1 }));
});
for (const input of [NaN, Infinity, undefined, () => {}, new Date()])
  test(`invalid JSON rejected: ${String(input)}`, () => {
    assert.throws(() => canonical(input));
  });
test("unsupported/missing/partial projections do not produce an empty pass", () => {
  assert.throws(() => syntheticControl({ ...subject.entry, id: "other" }, subject.production));
  assert.throws(() => syntheticControl(subject.entry, { programs: [] }));
  const s = { ...subject, production: { programs: [] } };
  const r = run(s);
  assert.equal(r.auditState, "INDETERMINATE");
  assert.equal(r.outcomes.length, 0);
});
test("an always-MATCH comparator fails semantic and integrity probes", () => {
  const s = { ...subject, compare: (a, p) => consistentVerdict(subject.compare(a, p), "MATCH") };
  const r = run(s);
  assert.equal(r.auditState, "FAILED");
  assert.equal(r.summary.semanticMissed, 34);
  assert.equal(r.summary.semanticDetected, 0);
});
test("an always-MISMATCH comparator fails the baseline; no fake kills", () => {
  const s = { ...subject, compare: (a, p) => consistentVerdict(subject.compare(a, p), "MISMATCH") };
  const r = run(s);
  assert.equal(r.auditState, "INDETERMINATE");
  assert.equal(r.summary.semanticDetected, 0);
  assert.equal(r.outcomes.length, 0);
});
test("all-mutants-INDETERMINATE is not semantic detection", () => {
  let calls = 0;
  const s = {
    ...subject,
    compare: (a, p) => {
      const original = subject.compare(a, p);
      return ++calls === 1 ? original : consistentVerdict(original, "INDETERMINATE");
    },
  };
  const r = run(s);
  assert.equal(r.summary.semanticDetected, 0);
  assert.equal(r.summary.semanticWrongClassification, 34);
  assert.equal(r.auditPassed, false);
});
test("crashing after a valid baseline is ERROR, not a detected mismatch", () => {
  let calls = 0;
  const s = {
    ...subject,
    compare: (a, p) => {
      if (++calls > 1) throw new Error("PRIVATE_SENTINEL never print me");
      return subject.compare(a, p);
    },
  };
  const r = run(s);
  assert.equal(r.summary.semanticDetected, 0);
  assert.equal(r.summary.semanticErrors, 34);
  assert.ok(!JSON.stringify(r).includes("PRIVATE_SENTINEL"));
});
test("throwing an unrelated error does not satisfy a binding rejection", () => {
  const s = {
    ...subject,
    compare: (a, p) => {
      try {
        return subject.compare(a, p);
      } catch {
        throw new Error("unrelated");
      }
    },
  };
  const r = run(s);
  assert.equal(r.summary.groups.binding.errors, 3);
  assert.equal(r.auditPassed, false);
});
test("a status/code-only comparator is exposed by body and post-state mutations", () => {
  const s = {
    ...subject,
    compare: (a, p) => {
      const r = subject.compare(a, p);
      if (r.verdict === "INDETERMINATE") return r;
      for (const row of r.rows) {
        row.comparison =
          row.production.status === row.local.status && row.production.code === row.local.code
            ? "MATCH"
            : "MISMATCH";
      }
      r.counts = {
        match: r.rows.filter((x) => x.comparison === "MATCH").length,
        mismatch: r.rows.filter((x) => x.comparison === "MISMATCH").length,
        indeterminate: 0,
      };
      r.verdict = r.counts.mismatch ? "MISMATCH" : "MATCH";
      return r;
    },
  };
  const r = run(s);
  assert.equal(r.auditPassed, false);
  assert.ok(r.summary.semanticMissed >= 10);
  assert.ok(r.summary.semanticDetected > 0);
  assert.equal(
    r.outcomes.find((x) => x.id === "post-state.boolean-instead-of-integer").observed,
    "MATCH",
  );
});
test("object-order-sensitive comparator is caught by the tolerance control", () => {
  const s = {
    ...subject,
    compare: (a, p) => {
      const r = subject.compare(a, p),
        id = "existing-was-deleted";
      const left = subject.production.programs[0].steps[id].production.body;
      const right = a?.[subject.entry.programId]?.steps?.[id]?.body;
      return r.verdict === "MATCH" && JSON.stringify(left) !== JSON.stringify(right)
        ? consistentVerdict(r, "MISMATCH")
        : r;
    },
  };
  const r = run(s);
  assert.equal(r.auditPassed, false);
  assert.equal(r.outcomes.find((x) => x.id === "object-keys.reordered").passed, false);
});
test("ignoring cleanup is caught by envelope probes", () => {
  const s = {
    ...subject,
    envelope: (comparison, execution) =>
      subject.envelope(comparison, { ...execution, cleanup: { state: "confirmed" } }),
  };
  const r = run(s);
  assert.equal(r.auditPassed, false);
  assert.equal(r.outcomes.find((x) => x.id === "envelope.cleanup-unconfirmed").passed, false);
});
test("malformed row counters cannot masquerade as semantic detection", () => {
  const s = {
    ...subject,
    compare: (a, p) => ({
      ...subject.compare(a, p),
      counts: { match: 999, mismatch: 0, indeterminate: 0 },
    }),
  };
  const r = run(s);
  assert.equal(r.auditState, "INDETERMINATE");
  assert.equal(r.outcomes.length, 0);
});
test("a comparator that edits its input is not accepted", () => {
  const s = {
    ...subject,
    compare: (a, p) => {
      const r = subject.compare(a, p);
      a.extra = {};
      return r;
    },
  };
  assert.equal(run(s).auditState, "INDETERMINATE");
});
test("a no-op mutation is named and not counted as a detection", async () => {
  const s = await fixtureSubject();
  s.production.programs[0].steps["non-atomic-batch"].production.message =
    "deliberately different diagnostic prose";
  const r = run(s);
  assert.equal(r.outcomes.find((x) => x.id === "message.non-atomic-batch").observed, "NO_OP");
  assert.equal(r.auditPassed, false);
});
test("known untested dimensions and diagnostic exclusions are visible", () => {
  const text = renderReport(good);
  for (const word of ["Array ordering", "Timestamp relationships", "Error prose", "not G1/G2"])
    assert.ok(text.includes(word));
  assert.ok(!text.includes("100%"));
  assert.match(text, /not a compatibility percentage/);
});
test("semantic catalog contains no newly invented array or Auth oracle", () => {
  const probes = buildProbes(subject.entry, syntheticControl(subject.entry, subject.production));
  assert.ok(
    probes.every((p) => !p.dimension.includes("tenant") && !p.dimension.includes("array-order")),
  );
});
for (const [label, args] of [
  ["missing output", ["--repo", "/tmp"]],
  ["relative output", ["--out", "relative"]],
  ["duplicate", ["--out", "/tmp/a", "--out", "/tmp/b"]],
  ["missing value", ["--out"]],
  ["unknown", ["--live", "true"]],
  ["no fixture fallback", ["--fixture", "true"]],
  ["no network backend", ["--backend", "production"]],
])
  test(`CLI refuses ${label}`, () => assert.throws(() => parseArgs(args)));
test("CLI parses only bounded offline arguments", () => {
  assert.equal(parseArgs([]).help, true);
  assert.equal(parseArgs(["--out", "/tmp/new", "--repo", "/tmp/repo"]).repo, "/tmp/repo");
});
async function fakeInstalled(extra = {}) {
  return {
    subject,
    identity: subject.identity,
    unchanged: async () => true,
    createOutput: async (p) => p,
    publish: async () => {},
    ...extra,
  };
}
async function cli(extra = {}) {
  const stdout = [],
    stderr = [];
  const code = await main(["--out", "/tmp/unused-audit"], {
    load: () => fakeInstalled(extra),
    stdout: (x) => stdout.push(x),
    stderr: (x) => stderr.push(x),
  });
  return { code, stdout, stderr };
}
test("CLI reports synthetic fixture validation truthfully in injection tests", async () => {
  const r = await cli();
  assert.equal(r.code, 0);
  const payload = JSON.parse(r.stdout[0]);
  assert.equal(payload.completeRepositoryValidation, false);
  assert.equal(payload.productionExecuted, false);
  assert.equal(payload.nativeRuntimeExecuted, false);
});
test("source changes after the audit invalidate a previously passing result", async () => {
  let saved;
  const r = await cli({
    unchanged: async () => false,
    publish: async (_, report) => {
      saved = report;
    },
  });
  assert.equal(r.code, 2);
  assert.equal(saved.auditPassed, false);
  assert.ok(saved.errors.includes("audit-source-changed"));
});
test("publication failure does not print a success or leak exception text", async () => {
  const r = await cli({
    publish: async () => {
      throw new Error("PRIVATE_PUBLICATION_SENTINEL");
    },
  });
  assert.equal(r.code, 2);
  assert.equal(r.stdout.length, 0);
  assert.ok(!r.stderr.join("").includes("PRIVATE_"));
});
test("an existing output rejection does not begin the audit", async () => {
  let compared = false;
  const r = await cli({
    createOutput: async () => {
      throw new Error("exists");
    },
    subject: {
      ...subject,
      compare: () => {
        compared = true;
      },
    },
  });
  assert.equal(r.code, 2);
  assert.equal(compared, false);
});
test("missing installed pilot fails closed, not a fixture or live fallback", async () => {
  const root = await mkdtemp(join(tmpdir(), "audit-missing-"));
  try {
    await assert.rejects(loadInstalled(root), /required-pilot-or-audit-not-installed/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test("symlinked installed source directories are refused", async () => {
  const root = await mkdtemp(join(tmpdir(), "audit-link-"));
  try {
    await mkdir(join(root, "conformance"));
    await symlink("/tmp", join(root, "conformance", "production-diff"));
    await assert.rejects(loadInstalled(root), /audit-source-symlink/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test("the actual CLI help works in a new process without repository inputs", () => {
  const text = execFileSync(
    process.execPath,
    [fileURLToPath(new URL("../audit.mjs", import.meta.url)), "--help"],
    { encoding: "utf8" },
  );
  assert.match(text, /no live mode/);
});
test("report exit codes distinguish pass, failing audit and inconclusive execution", () => {
  assert.equal(auditExitCode(good), 0);
  assert.equal(auditExitCode({ ...good, auditPassed: false, auditState: "FAILED" }), 1);
  assert.equal(auditExitCode({ ...good, auditPassed: false, auditState: "INDETERMINATE" }), 2);
});

test("whole fixture audit attempts neither network nor a subprocess", () => {
  const result = JSON.parse(
    execFileSync(process.execPath, [fileURLToPath(new URL("offline-check.mjs", import.meta.url))], {
      encoding: "utf8",
    }),
  );
  assert.equal(result.auditPassed, true);
  assert.equal(result.networkAttempts, 0);
  assert.equal(result.processAttempts, 0);
  assert.equal(result.completeRepositoryValidation, false);
});
