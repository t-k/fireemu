import assert from "node:assert/strict";
import test from "node:test";
import { compareManagement, sha256 } from "./storage-rules/management-compare.mjs";
import { binding, provenance, localFixture } from "./storage-rules-management-local.test.mjs";

async function fixture() {
  const { result: local } = await localFixture();
  const production = {
    schemaVersion: 1,
    kind: "production-management-projection",
    runId: "unit-fixture",
    sourceCommit: "c".repeat(40),
    journalSha256: "d".repeat(64),
    binding,
    rows: structuredClone(local.rows),
    gaps: ["invalid release was absent"],
    unjudgedHeaders: ["date", "x-guploader-uploadid"],
  };
  for (const row of production.rows) {
    if (row.dialect === "control") row.dialect = "firebase-rules";
    row.evidence = { runId: production.runId, sequence: row.evidence.ordinal, operationId: row.id };
  }
  const receipt = {
    schemaVersion: 1,
    profile: "strict",
    binding,
    localProvenance: provenance,
    production: {
      runId: production.runId,
      sourceCommit: production.sourceCommit,
      journalSha256: production.journalSha256,
    },
  };
  return { local: structuredClone(local), production, receipt: structuredClone(receipt) };
}
const compare = ({ local, production, receipt }) => compareManagement(local, production, receipt);

test("paired effects can match while the original production atomicity gap stays OPEN", async () => {
  const result = compare(await fixture());
  assert.equal(result.pairedEffectsMatch, true);
  assert.equal(result.closureReady, false);
  assert.ok(
    result.gaps.includes("MISSING_PRODUCTION_INVALID_INSTALLED_IDENTITY_AND_EFFECTIVE_WITNESS"),
  );
  assert.deepEqual(result.unjudgedHeaders, ["date", "x-guploader-uploadid"]);
});

const tamperCases = {
  "zero rows": (f) => {
    f.local.rows = [];
  },
  "missing step": (f) => {
    f.local.rows.pop();
  },
  "duplicate step": (f) => {
    f.local.rows[1] = f.local.rows[0];
  },
  "extra step": (f) => {
    f.local.rows.push(f.local.rows[0]);
  },
  "collection error": (f) => {
    f.local.errors.push({ kind: "failed" });
  },
  "wrong profile": (f) => {
    f.local.profile = "emulator";
  },
  "wrong caller": (f) => {
    f.local.rows.find((r) => r.id.endsWith("/subject")).caller = "anonymous";
  },
  "wrong dialect": (f) => {
    f.local.rows.find((r) => r.id.endsWith("/subject")).dialect = "gcs";
  },
  "wrong source": (f) => {
    f.local.rows.find((r) => r.kind === "compile").sourceSha256 = "f".repeat(64);
  },
  "stale binary": (f) => {
    f.local.provenance.binarySha256 = "f".repeat(64);
  },
  "stale corpus": (f) => {
    f.local.provenance.corpusSha256 = "f".repeat(64);
  },
  "wrong fixture": (f) => {
    f.local.binding.uidA = "foreign";
  },
  "foreign production run": (f) => {
    f.production.rows[0].evidence.runId = "foreign";
  },
  "missing raw body": (f) => {
    delete f.local.rows[0].response.bodyBase64;
  },
  "wrong raw length": (f) => {
    f.local.rows[0].response.bodyBytes++;
  },
  "extra field": (f) => {
    f.local.rows[0].accepted = true;
  },
  "compile refused": (f) => {
    f.local.rows.find((r) => r.kind === "compile").effect.sourceAccepted = false;
  },
  "invalid accepted": (f) => {
    f.local.rows.find((r) => r.kind === "rejection").effect.rejected = false;
  },
  "installed source changed": (f) => {
    f.local.localOnly[4].sourceSha256 = "f".repeat(64);
  },
  "invalid witness changed": (f) => {
    f.local.localOnly[5].response.status = 403;
  },
  "local-only missing": (f) => {
    f.local.localOnly.pop();
  },
  "switch reversed": (f) => {
    f.local.rows.find((r) => r.id === "management/A/control-4/subject").evidence.ordinal = 1;
  },
  "switch old allow retained": (f) => {
    f.local.rows.find((r) => r.id === "management/B/control-3/subject").response.status = 200;
  },
  "Admin state changed": (f) => {
    f.local.rows.find((r) => r.id === "management/A/control-3/after-metadata").effect.stateSha256 =
      "f".repeat(64);
  },
  "no-release emulator403": (f) => {
    f.local.rows.find((r) => r.id === "management/no-release/final/subject").response.status = 403;
  },
  "no-release Admin changed": (f) => {
    f.local.rows.find(
      (r) => r.id === "management/no-release/final/after-metadata",
    ).effect.stateSha256 = "f".repeat(64);
  },
  "cleanup absent missing": (f) => {
    f.local.rows.find((r) => r.id === "management/control-5/absence-media").response.status = 200;
  },
  "wrong stable header": (f) => {
    f.local.rows.find((r) => r.id === "management/no-release/final/subject").response.headers[
      "x-content-type-options"
    ] = null;
  },
  "missing production body": (f) => {
    delete f.production.rows[0].response.bodyBase64;
  },
};
for (const [name, tamper] of Object.entries(tamperCases))
  test(`judge rejects ${name}`, async () => {
    const f = await fixture();
    tamper(f);
    assert.equal(compare(f).pairedEffectsMatch, false);
  });

test("equal parsed JSON with different byte layout is refused", async () => {
  const f = await fixture();
  const row = f.local.rows.find((r) => r.id === "management/no-release/final/subject");
  const bytes = Buffer.from("missing release\n");
  row.response.bodyBase64 = bytes.toString("base64");
  row.response.bodyBytes = bytes.length;
  row.response.bodySha256 = sha256(bytes);
  row.response.headers["content-length"] = String(bytes.length);
  assert.equal(compare(f).mismatches[0].kind, "STORAGE_BYTES_OR_HEADERS");
});

test("generated insertion orders do not widen the closed accepted set", async () => {
  for (let shift = 0; shift < 24; shift++) {
    const f = await fixture();
    f.local.rows = [...f.local.rows.slice(shift), ...f.local.rows.slice(0, shift)];
    f.production.rows.reverse();
    assert.equal(compare(f).pairedEffectsMatch, true);
    f.local.rows.splice(shift, 1);
    assert.equal(compare(f).pairedEffectsMatch, false);
  }
});

test("actual collector state corruption is rejected by the actual judge", async () => {
  const f = await fixture();
  f.local = (await localFixture({ corruptInvalid: true })).result;
  assert.equal(compare(f).pairedEffectsMatch, false);
});

test("metadata state claims are bound to the captured raw response", async () => {
  const f = await fixture();
  for (const stage of ["before-metadata", "after-metadata"])
    f.local.rows.find((r) => r.id === `management/A/control-3/${stage}`).effect.stateSha256 =
      "f".repeat(64);
  assert.equal(compare(f).pairedEffectsMatch, false);
});

test("installed source claims are bound to the actual local readback", async () => {
  const f = await fixture();
  const row = f.local.rows.find((r) => r.kind === "identity");
  const bytes = Buffer.from(JSON.stringify({ loaded: true, source: "different source" }));
  row.response.bodyBase64 = bytes.toString("base64");
  row.response.bodyBytes = bytes.length;
  row.response.bodySha256 = sha256(bytes);
  row.response.headers["content-length"] = String(bytes.length);
  assert.equal(compare(f).pairedEffectsMatch, false);
});

test("matching receipt labels cannot substitute for actual fixture bytes", async () => {
  const f = await fixture();
  f.local.provenance.fixtureSha256 = f.receipt.localProvenance.fixtureSha256 = "f".repeat(64);
  assert.equal(compare(f).pairedEffectsMatch, false);
});

test("an extra unique observation cannot widen the required scope", async () => {
  const f = await fixture();
  const extra = structuredClone(f.local.rows[0]);
  extra.id = "unexpected/step";
  f.local.rows.push(extra);
  assert.equal(compare(f).pairedEffectsMatch, false);
});

test("local atomic identity labels must equal the actual before and after source", async () => {
  const f = await fixture();
  const row = f.local.localOnly[4];
  const bytes = Buffer.from(JSON.stringify({ loaded: true, source: "different source" }));
  row.response.bodyBase64 = bytes.toString("base64");
  row.response.bodyBytes = bytes.length;
  row.response.bodySha256 = sha256(bytes);
  row.response.headers["content-length"] = String(bytes.length);
  assert.equal(compare(f).pairedEffectsMatch, false);
});

test("production source reference digests cannot borrow another compiled source", async () => {
  const f = await fixture();
  f.production.rows.find((r) => r.kind === "compile").sourceSha256 = "f".repeat(64);
  assert.equal(compare(f).pairedEffectsMatch, false);
});

test("source identity must precede its corresponding effective decision", async () => {
  const f = await fixture();
  f.local.rows.find((r) => r.id === "release/A/after").evidence.ordinal = 99999;
  assert.equal(compare(f).pairedEffectsMatch, false);
});

test("owned baseline must be an actual absent read before seeding", async () => {
  const f = await fixture();
  const baseline = f.local.rows.find((r) => r.id === "management/control-5/baseline-media");
  assert.ok(baseline);
  baseline.response.status = 200;
  assert.equal(compare(f).pairedEffectsMatch, false);
});

test("local rejection effects must have an actual rejection status", async () => {
  const f = await fixture();
  f.local.rows.find((r) => r.kind === "rejection").response.status = 200;
  assert.equal(compare(f).pairedEffectsMatch, false);
});
