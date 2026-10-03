import assert from "node:assert/strict";
import test from "node:test";
import { captureResponse, compareManagement, sha256 } from "./storage-rules/management-compare.mjs";
import {
  binding,
  provenance,
  localFixture,
  wireResponse,
} from "./storage-rules-management-local.test.mjs";

import { buildCorpus } from "./storage-rules/corpus.mjs";

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
    sourceEvidence: [],
  };
  for (const row of production.rows) {
    if (row.dialect === "control") row.dialect = "firebase-rules";
    row.evidence = {
      runId: production.runId,
      sequence: row.evidence.ordinal * 2,
      operationId: row.id,
    };
    if (row.kind === "compile" || row.kind === "clear") replaceBody(row, {}, 200);
    if (row.kind === "absence") replaceBody(row, { error: { code: 404 } }, 404);
    if (row.kind === "rejection")
      replaceBody(
        row,
        {
          issues: [
            {
              severity: "ERROR",
              sourcePosition: { fileName: "storage.rules", line: 5, column: 21 },
            },
          ],
        },
        200,
      );
    if (row.kind === "identity") {
      const sourceId = row.sourceRef.split("/")[1];
      const [, switched] = buildCorpus(binding).managementPrograms;
      const name = `projects/fireemu-oracle-query/rulesets/fixture-${sourceId}`;
      replaceBody(row, { name: switched.releaseName, rulesetName: name }, 200);
      production.sourceEvidence.push({
        runId: production.runId,
        sequence: row.evidence.sequence - 1,
        operationId: `ruleset/${sourceId}/read-source`,
        sourceRef: row.sourceRef,
        response: captureResponse(
          wireResponse(
            200,
            JSON.stringify({
              name,
              source: {
                files: [{ name: "storage.rules", content: switched[`source${sourceId}`] }],
              },
            }),
          ),
        ),
      });
    }
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
      projectionSha256: sha256(Buffer.from(JSON.stringify(production))),
    },
  };
  return { local: structuredClone(local), production, receipt: structuredClone(receipt) };
}
const compare = ({ local, production, receipt }) => compareManagement(local, production, receipt);
function reseal(f) {
  if (Object.hasOwn(f.receipt.production, "projectionSha256"))
    f.receipt.production.projectionSha256 = sha256(Buffer.from(JSON.stringify(f.production)));
}
function replaceBody(row, value, status = row.response.status) {
  const bytes = Buffer.from(JSON.stringify(value));
  row.response.status = status;
  row.response.bodyBase64 = bytes.toString("base64");
  row.response.bodyBytes = bytes.length;
  row.response.bodySha256 = sha256(bytes);
  row.response.headers["content-length"] = String(bytes.length);
  if (row.kind === "metadata") row.effect.stateSha256 = row.response.bodySha256;
}

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
    reseal(f);
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
  reseal(f);
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

for (const side of ["local", "production"]) {
  test(`M1 ${side} Admin present metadata cannot be two rejection responses`, async () => {
    const f = await fixture();
    for (const stage of ["before-metadata", "after-metadata"])
      f[side].rows.find((r) => r.id === `management/A/control-3/${stage}`).response.status = 403;
    reseal(f);
    assert.equal(compare(f).pairedEffectsMatch, false);
  });
  test(`M1 ${side} source switch cannot change owned generation`, async () => {
    const f = await fixture();
    for (const stage of ["before-metadata", "after-metadata"]) {
      const row = f[side].rows.find((r) => r.id === `management/B/control-3/${stage}`);
      const body = JSON.parse(Buffer.from(row.response.bodyBase64, "base64"));
      body.generation = String(BigInt(body.generation) + 1n);
      replaceBody(row, body);
    }
    reseal(f);
    assert.equal(compare(f).pairedEffectsMatch, false);
  });
  test(`M2 ${side} final before-media must precede the no-release subject`, async () => {
    const f = await fixture();
    f[side].rows.find((r) => r.id === "management/no-release/final/before-media").evidence[
      side === "local" ? "ordinal" : "sequence"
    ] = 99999;
    reseal(f);
    assert.equal(compare(f).pairedEffectsMatch, false);
  });
  test(`M2 ${side} entry Admin readback must precede the no-release subject`, async () => {
    const f = await fixture();
    f[side].rows.find((r) => r.id === "management/no-release/entry/after-media").evidence[
      side === "local" ? "ordinal" : "sequence"
    ] = 1;
    reseal(f);
    assert.equal(compare(f).pairedEffectsMatch, false);
  });
}
for (const [name, tamper] of Object.entries({
  "compile200 success raw status": (f) => {
    f.production.rows.find((r) => r.kind === "compile").response.status = 400;
  },
  "absence404 raw status": (f) => {
    f.production.rows.find((r) => r.kind === "absence").response.status = 200;
  },
  "invalid-test error issue": (f) => {
    replaceBody(
      f.production.rows.find((r) => r.kind === "rejection"),
      {},
      200,
    );
  },
  "LOCAL_ONLY sourceA": (f) => {
    for (const row of [f.local.localOnly[0], f.local.localOnly[4]]) {
      replaceBody(row, { loaded: true, source: "foreign source" });
      row.sourceSha256 = sha256("foreign source");
    }
  },
  "LOCAL_ONLY invalid-source": (f) => {
    f.local.localOnly[3].sourceSha256 = "f".repeat(64);
  },
  "LOCAL_ONLY witness null source": (f) => {
    f.local.localOnly[1].sourceSha256 = "f".repeat(64);
  },
  "unjudged stable content-type": (f) => {
    f.production.unjudgedHeaders = ["content-type"];
  },
  "unjudged header type": (f) => {
    f.production.unjudgedHeaders = [42];
  },
  "unjudged unknown header": (f) => {
    f.production.unjudgedHeaders = ["arbitrary-header"];
  },
}))
  test(`review regression rejects ${name}`, async () => {
    const f = await fixture();
    tamper(f);
    reseal(f);
    assert.equal(compare(f).pairedEffectsMatch, false);
  });

test("the independently frozen projection cannot be replaced while retaining its receipt", async () => {
  const f = await fixture();
  f.production.gaps.push("relabeled after freeze");
  assert.equal(compare(f).pairedEffectsMatch, false);
});

test("Admin media rejection cannot stand for preserved readable object bytes", async () => {
  const f = await fixture();
  for (const side of ["local", "production"])
    for (const stage of ["before-media", "after-media"])
      f[side].rows.find((r) => r.id === `management/A/control-3/${stage}`).response.status = 403;
  reseal(f);
  assert.equal(compare(f).pairedEffectsMatch, false);
});

for (const [name, tamper] of Object.entries({
  "source readback missing": (f) => {
    f.production.sourceEvidence.pop();
  },
  "source readback foreign content": (f) => {
    replaceBody(
      { response: f.production.sourceEvidence[0].response },
      {
        name: "projects/fireemu-oracle-query/rulesets/fixture-A",
        source: { files: [{ name: "storage.rules", content: "foreign source" }] },
      },
    );
  },
  "release mismatches native source": (f) => {
    const row = f.production.rows.find((r) => r.id === "release/A/after");
    const body = JSON.parse(Buffer.from(row.response.bodyBase64, "base64"));
    body.rulesetName = "projects/fireemu-oracle-query/rulesets/foreign";
    replaceBody(row, body);
  },
  "source evidence foreign run": (f) => {
    f.production.sourceEvidence[0].runId = "foreign-run";
  },
  "clear absence after final request": (f) => {
    f.production.rows.find((r) => r.id === "release/restore/bucket-absence").evidence.sequence =
      99999;
  },
  "prefix cleanup before object absence": (f) => {
    f.local.rows.find((r) => r.id === "management/prefix-empty").evidence.ordinal = 1;
  },
}))
  test(`authority and chronology reject ${name}`, async () => {
    const f = await fixture();
    tamper(f);
    reseal(f);
    assert.equal(compare(f).pairedEffectsMatch, false);
  });
