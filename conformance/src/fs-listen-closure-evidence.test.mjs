import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { closureEvidence } from "./fs-listen/closure-evidence.mjs";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const runs = [
  ["listen-l1-native-20261005T002459Z-r1", "native-prod.json", "native"],
  ["listen-l1-native-20261005T013618Z-r2", "native-prod.json", "native"],
  ["listen-l1-sdk-20261005T004425Z-r1", "sdk-prod.json", "sdk"],
  ["listen-l1-sdk-20261005T013136Z-r2", "sdk-prod.json", "sdk"],
  ["listen-l1b-native-20261005T115528Z-r1", "l1b-prod.json", "native"],
  ["listen-l1b-native-20261005T123312Z-r2", "l1b-prod.json", "native"],
  ["listen-l2-browser-20261005T135910Z-r1", "browser-prod.json", "browser"],
  ["listen-l2-browser-20261005T145934Z-r2", "browser-prod.json", "browser"],
  ["listen-l3-browser-20261006T050949Z-r1", "browser-prod.json", "browser"],
];
const condition = "FS-LISTEN-SDK/raw-resume-token";
const real203 = new URL("../../target/codex-out/listen-closure-real-203.json", import.meta.url);
const row = (n = 1) => ({
  conditions: [condition],
  rows: [{ kind: "documentChange", doc: "a", fields: { n }, targetIds: [1], removedTargetIds: [] }],
  timedOut: false,
  end: null,
});

function fixture(t) {
  mkdirSync(new URL("../../target/codex-out/", import.meta.url), { recursive: true });
  const dir = mkdtempSync(new URL("../../target/codex-out/listen-test-", import.meta.url));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const binary = join(dir, "fireemu");
  writeFileSync(binary, "test binary");
  const options = {
    binary,
    "production-root": dir,
    out: join(dir, "comparison.json"),
    summary: join(dir, "summary.md"),
  };
  const write = (file, value) => {
    mkdirSync(resolve(file, ".."), { recursive: true });
    writeFileSync(file, JSON.stringify(value));
  };
  const recordings = runs.map(([name, file, kind], i) => {
    const rows =
      kind === "native"
        ? { "native/resume-token/current": row() }
        : {
            "sdk/101": { ...row(), conditions: ["FS-LISTEN-SDK/document-event-order"] },
          };
    if (i === 8)
      rows["browser-streaming/sdk/202"] = {
        l3: true,
        conditions: ["FS-LISTEN-SDK/browser-tab-lifecycle"],
        observed: [{ terminate: [] }],
      };
    const value = { version: 1, kind, run: name, cleanup: { complete: true }, errors: {}, rows };
    const path = join(dir, name, file);
    write(path, value);
    return { path, value };
  });
  for (const [key, index] of [
    ["native", 0],
    ["sdk", 2],
    ["l1b", 4],
    ["browser", 8],
  ]) {
    const value = structuredClone(recordings[index].value);
    value.provenance = {
      target: "local",
      profile: "strict",
      binarySha256: digest(readFileSync(binary)),
      sourceCommit: "1".repeat(40),
      buildInputs: { dirty: false, inputsSha256: "2".repeat(64) },
      binaryBuiltAfterSource: true,
    };
    const path = join(dir, `${key}.json`);
    write(path, value);
    options[`local-${key}`] = path;
  }
  return { options, recordings, write };
}

test("evidence binds each condition case to the recording bytes, binary and current runner", async (t) => {
  const { options, recordings } = fixture(t);
  const evidence = await closureEvidence(options);
  const bound = evidence.rows.find((r) => r.conditionId === condition);
  assert.equal(bound.status, "MATCH");
  assert.equal(bound.production.sha256, digest(readFileSync(recordings[0].path)));
  assert.equal(bound.binarySha256, digest(readFileSync(options.binary)));
  assert.equal(bound.runnerTree, evidence.runnerTree.workingTreeSha256);
  assert.ok(evidence.conditions.every((c) => c.blockers.some((b) => /source head/.test(b))));
  assert.equal(evidence.conditions.length, 15);
  assert.equal(evidence.rows.filter((r) => r.row === "native/resume-token/current").length, 4);
  assert.ok(!JSON.stringify(evidence).includes(options["production-root"]));
});

test(
  "real 203 windows name D7 after removing D4 and D5 and reject any remaining difference",
  { skip: !existsSync(real203) },
  async (t) => {
    const { options, recordings, write } = fixture(t);
    const real = JSON.parse(readFileSync(real203));
    const local = JSON.parse(readFileSync(options["local-browser"]));
    Object.assign(recordings[8].value.rows, real.production);
    Object.assign(local.rows, real.local);
    write(recordings[8].path, recordings[8].value);
    write(options["local-browser"], local);
    let evidence = await closureEvidence(options);
    for (const [id, differences] of [
      ["browser-streaming/sdk/203", ["D4", "D7(a)", "D7(b)"]],
      ["browser-long-polling/sdk/203", ["D4", "D5", "D7(a)", "D7(b)"]],
      ["browser-streaming/sdk/203C", ["D5"]],
    ]) {
      const compared = evidence.rows.find((r) => r.row === id);
      assert.deepEqual(
        compared.differences.map((d) => d.id),
        differences,
        id,
      );
      assert.ok(compared.differences.every((d) => d.approved));
      for (const d of compared.differences.filter((d) => d.id.startsWith("D7")))
        assert.match(d.ruling, /13:26Z.*M1/);
    }
    local.rows["browser-streaming/sdk/203"].observed[0].phases[2].errors = ["permission-denied"];
    write(options["local-browser"], local);
    evidence = await closureEvidence(options);
    const compared = evidence.rows.find((r) => r.row === "browser-streaming/sdk/203");
    assert.ok(
      compared.differences.some((d) => d.id === "unclassified-canonical-difference" && !d.approved),
    );
  },
);

test("registered differences remain DIVERGES and variable production is judged against both answers", async (t) => {
  const { options, recordings, write } = fixture(t);
  const local = JSON.parse(readFileSync(options["local-native"]));
  local.rows["native/resume-token/current"] = row(2);
  write(options["local-native"], local);
  let evidence = await closureEvidence(options);
  let rows = evidence.rows.filter((r) => r.production.run === runs[0][0]);
  assert.equal(rows[0].status, "DIVERGES");
  assert.equal(rows[0].comparatorResult, "MISMATCH");
  assert.equal(rows[0].declaredDifference.approved, false);
  assert.match(rows[0].declaredDifference.source, /divergences-strict/);
  recordings[1].value.rows["native/resume-token/current"] = row(3);
  write(recordings[1].path, recordings[1].value);
  evidence = await closureEvidence(options);
  rows = evidence.rows.filter((r) => r.production.run === runs[0][0]);
  assert.equal(rows[0].status, "DIVERGES");
  assert.equal(rows[0].comparatorResult, "NONDETERMINISTIC");
  assert.deepEqual(rows[0].matchedProductionRuns, []);
  local.rows["native/resume-token/current"] = row(3);
  write(options["local-native"], local);
  evidence = await closureEvidence(options);
  rows = evidence.rows.filter((r) => r.packet === "native");
  assert.ok(rows.every((r) => r.status === "MATCH"));
  assert.ok(rows.every((r) => r.matchedProductionRuns.join() === runs[1][0]));
  assert.ok(rows.every((r) => r.productionAnswers.length === 2));
  local.rows["native/resume-token/current"] = row();
  write(options["local-native"], local);
  evidence = await closureEvidence(options);
  assert.ok(
    evidence.rows
      .filter((r) => r.packet === "native")
      .every((r) => r.matchedProductionRuns.join() === runs[0][0]),
  );
});

test("L3 is never duplicated into a production pair and empty terminate leaves the clause unobserved", async (t) => {
  const { options } = fixture(t);
  const evidence = await closureEvidence(options);
  const l3 = evidence.rows.filter((r) => r.production.run === runs[8][0]);
  assert.ok(l3.every((r) => r.productionRecordings === 1 && /921/.test(r.recordingNote)));
  const close = l3.find((r) => r.row.endsWith("/202"));
  assert.equal(close.status, "MATCH");
  assert.equal(close.terminateOnTabClose, "UNOBSERVED");
  assert.match(
    evidence.conditions
      .find((c) => c.conditionId.endsWith("/browser-tab-lifecycle"))
      .blockers.join(),
    /source head/,
  );
});

test("missing rows and incomplete cleanup cannot become matches", async (t) => {
  const { options, write } = fixture(t);
  const local = JSON.parse(readFileSync(options["local-browser"]));
  local.rows = {};
  local.cleanup.complete = false;
  write(options["local-browser"], local);
  const evidence = await closureEvidence(options);
  assert.ok(
    evidence.rows
      .filter((r) => r.production.kind === "browser")
      .every((r) => r.status === "NOT_COMPARABLE"),
  );
});

test("a supplied local recording of another binary or profile is refused", async (t) => {
  const { options, write } = fixture(t);
  const local = JSON.parse(readFileSync(options["local-native"]));
  local.provenance.binarySha256 = "0".repeat(64);
  write(options["local-native"], local);
  await assert.rejects(closureEvidence(options), /binary or strict profile/);
});

test("L3 cache differences retain the latest browser verdict and raw byte counts", async (t) => {
  const { options, recordings, write } = fixture(t);
  const id = "browser-streaming/sdk/203";
  const cache = {
    l3: true,
    conditions: ["FS-LISTEN-SDK/backend-cache-transitions"],
    observed: [
      {
        phases: [{ phase: "warm", snapshots: [], errors: [] }],
        wire: [{ phase: "warm", targets: [{}], addTargetBodies: [], requestBodyBytes: 100 }],
      },
    ],
  };
  recordings[8].value.rows[id] = structuredClone(cache);
  write(recordings[8].path, recordings[8].value);
  const local = JSON.parse(readFileSync(options["local-browser"]));
  local.rows[id] = structuredClone(cache);
  local.rows[id].observed[0].wire[0].requestBodyBytes = 999;
  write(options["local-browser"], local);
  let evidence = await closureEvidence(options);
  let compared = evidence.rows.find((r) => r.row === id);
  assert.equal(compared.status, "MATCH");
  assert.equal(compared.bodyBytes.production[0].request, 100);
  assert.equal(compared.bodyBytes.local[0].request, 999);
  assert.equal(compared.requestByteCounts.judgement, "RECORDED_NOT_JUDGED");
  assert.match(compared.requestByteCounts.source, /13:26Z M4/);
  local.rows[id].observed[0].phases[0].errors = ["permission-denied"];
  write(options["local-browser"], local);
  evidence = await closureEvidence(options);
  compared = evidence.rows.find((r) => r.row === id);
  assert.equal(compared.status, "DIVERGES");
  assert.deepEqual(
    compared.differences.map((d) => d.id),
    ["unclassified-canonical-difference"],
  );
});

test("shared native lifecycle cases bind both declared conditions without admitting transaction cases", async (t) => {
  const { options, recordings, write } = fixture(t);
  for (const item of recordings.slice(0, 2)) {
    item.value.rows["native/target-lifecycle/open"] = {
      ...row(),
      conditions: ["FS-LISTEN-SDK/default-subscription", "FS-LISTEN-SDK/native-target-protocol"],
    };
    item.value.rows["native/commit-atomic-visibility/open"] = {
      ...row(),
      conditions: ["FS-TRANSACTION/commit-atomic-visibility"],
    };
    write(item.path, item.value);
  }
  const evidence = await closureEvidence(options);
  const shared = evidence.rows.filter((r) => r.row === "native/target-lifecycle/open");
  assert.equal(shared.length, 4);
  assert.ok(shared.every((r) => r.status === "NOT_COMPARABLE"));
  assert.ok(evidence.rows.every((r) => r.conditionId.startsWith("FS-LISTEN-SDK/")));
});

test("duplicate production run identities are refused", async (t) => {
  const { options, recordings, write } = fixture(t);
  recordings[1].value.run = recordings[0].value.run;
  write(recordings[1].path, recordings[1].value);
  await assert.rejects(closureEvidence(options), /distinct runs/);
});

test("the real 203C token relationship difference is named and not covered by D4 or D5", async (t) => {
  const { options, recordings, write } = fixture(t);
  const id = "browser-long-polling/sdk/203C";
  const productionCache = {
    l3: true,
    conditions: ["FS-LISTEN-SDK/backend-cache-transitions"],
    observed: [
      {
        wire: [
          {
            phase: "cold-online",
            event: 1,
            targets: [{}],
            addTargetBodies: [],
          },
          {
            phase: "cold-online",
            event: 2,
            boundaryComplete: true,
            boundaryBodyBytes: 1469,
            body: JSON.stringify([
              [
                4,
                [
                  {
                    targetChange: { targetChangeType: "CURRENT", resumeToken: "AAAAAAAAAAAAAAA=" },
                  },
                ],
              ],
              [5, [{ targetChange: { resumeToken: "BBBBBBBBBBBBBBB=" } }]],
            ]),
            boundaries: [13, 13].map((relation, i) => ({
              sequence: i + 4,
              type: i === 0 ? "CURRENT" : "NO_CHANGE",
              resumeToken: { relation },
              readTime: "2026-10-06T05:12:24.737425Z",
            })),
          },
        ],
      },
    ],
  };
  const body = productionCache.observed[0].wire[1].body;
  productionCache.observed[0].wire[1].body = `${Buffer.byteLength(body)}\n${body}`;
  recordings[8].value.rows[id] = productionCache;
  write(recordings[8].path, recordings[8].value);
  const local = JSON.parse(readFileSync(options["local-browser"]));
  local.rows[id] = structuredClone(productionCache);
  local.rows[id].observed[0].wire[1].boundaries.forEach((boundary, i) => {
    boundary.resumeToken.relation = i + 1;
  });
  local.rows[id].observed[0].wire[1].boundaryBodyBytes = 1018;
  write(options["local-browser"], local);
  const evidence = await closureEvidence(options);
  const compared = evidence.rows.find((r) => r.row === id);
  assert.equal(compared.status, "DIVERGES");
  assert.deepEqual(
    compared.differences.map((d) => d.id),
    ["boundary-token-relationship", "unclassified-canonical-difference"],
  );
  assert.equal(compared.differences[0].approved, false);
  assert.equal(compared.bodyBytes.production[0].response, 1469);
  assert.equal(compared.bodyBytes.local[0].response, 1018);
  assert.match(compared.reason, /CURRENT.*NO_CHANGE.*token/);
  assert.ok(
    evidence.conditions
      .find((c) => c.conditionId.endsWith("/backend-cache-transitions"))
      .blockers.some((b) => /boundary-token-relationship/.test(b)),
  );
});

test("variable browser production cites the matching run and never borrows incomplete cleanup", async (t) => {
  const { options, recordings, write } = fixture(t);
  recordings[7].value.rows["sdk/101"] = {
    ...row(2),
    conditions: ["FS-LISTEN-SDK/document-event-order"],
  };
  write(recordings[7].path, recordings[7].value);
  const local = JSON.parse(readFileSync(options["local-browser"]));
  local.rows["sdk/101"] = structuredClone(recordings[7].value.rows["sdk/101"]);
  write(options["local-browser"], local);
  let evidence = await closureEvidence(options);
  let compared = evidence.rows.filter((r) => r.packet === "l2" && r.row === "sdk/101");
  assert.ok(
    compared.every((r) => r.status === "MATCH" && r.matchedProductionRuns.join() === runs[7][0]),
  );
  recordings[7].value.cleanup.complete = false;
  write(recordings[7].path, recordings[7].value);
  evidence = await closureEvidence(options);
  compared = evidence.rows.filter((r) => r.packet === "l2" && r.row === "sdk/101");
  assert.ok(compared.every((r) => r.status === "NOT_COMPARABLE"));
});

test("variable production retains informative existence-filter contents without new masking", async (t) => {
  const { options, recordings, write } = fixture(t);
  const id = "native/filter-variation/open";
  for (const [i, item] of recordings.slice(0, 2).entries()) {
    item.value.rows[id] = row();
    item.value.rows[id].rows.unshift({
      kind: "filter",
      targetId: 1,
      count: i + 1,
      unchangedNames: { hashCount: 1, bitmapBytes: 8, padding: 0 },
    });
    write(item.path, item.value);
  }
  const local = JSON.parse(readFileSync(options["local-native"]));
  local.rows[id] = structuredClone(recordings[0].value.rows[id]);
  local.rows[id].rows[0].count = 3;
  write(options["local-native"], local);
  let evidence = await closureEvidence(options);
  assert.ok(
    evidence.rows
      .filter((r) => r.row === id)
      .every((r) => r.status === "DIVERGES" && r.matchedProductionRuns.length === 0),
  );
  local.rows[id].rows[0].count = 2;
  write(options["local-native"], local);
  evidence = await closureEvidence(options);
  assert.ok(
    evidence.rows
      .filter((r) => r.row === id)
      .every((r) => r.status === "MATCH" && r.matchedProductionRuns.join() === runs[1][0]),
  );
});

test("an unlisted registered native row stays unapproved even when its strict sequence matches", async (t) => {
  const { options, recordings, write } = fixture(t);
  const local = JSON.parse(readFileSync(options["local-native"]));
  local.rows["native/resume-token/current"] = {
    ...row(),
    rows: [
      { kind: "targetChange", type: "ADD", targetIds: [1], resumeToken: false },
      { kind: "boundary", resumeToken: true },
      { kind: "documentChange", doc: "b", fields: {}, targetIds: [1], removedTargetIds: [] },
      { kind: "targetChange", type: "CURRENT", targetIds: [1], resumeToken: true },
      { kind: "boundary", resumeToken: true },
      {
        kind: "filter",
        targetId: 1,
        count: 2,
        unchangedNames: { hashCount: 0, bitmapBytes: 0, padding: 0 },
      },
    ],
  };
  write(options["local-native"], local);
  let evidence = await closureEvidence(options);
  let compared = evidence.rows.find((r) => r.packet === "native");
  assert.equal(compared.comparatorResult, "KNOWN_DIVERGENCE");
  assert.equal(compared.declaredDifference.approved, false);
  for (const [i, run] of ["nmuuicyas", "nmuukwo6n"].entries()) {
    recordings[i].value.run = run;
    write(recordings[i].path, recordings[i].value);
  }
  evidence = await closureEvidence(options);
  compared = evidence.rows.find((r) => r.packet === "native");
  assert.equal(compared.declaredDifference.approved, true);
});
