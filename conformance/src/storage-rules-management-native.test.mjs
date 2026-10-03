import assert from "node:assert/strict";
import test from "node:test";
import { buildNativeManifest } from "./storage-rules/management-native-manifest.mjs";

export function nativeParams(branch = "absent") {
  return {
    runId: "native-mock-a", sourceCommit: "7b4861263943cd17f455051c1c4878ff27f5e982", sourceTree: "54ea32bcd98ecc7f733555146244ed62a66246dc",
    bucket: "fireemu-oracle-query.firebasestorage.app",
    baseline: branch === "absent" ? { kind: "absent", observedAt: 1000, bucketAbsent: true, bucketlessAbsent: true } : {
      kind: "present", observedAt: 1000,
      release: { name: "projects/fireemu-oracle-query/releases/firebase.storage/fireemu-oracle-query.firebasestorage.app", rulesetName: "projects/fireemu-oracle-query/rulesets/baseline", updateTime: "2026-10-03T00:00:00Z" },
      source: "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow get: if true; } } }", bucketlessAbsent: true,
    },
    limits: { settleCycles: 4, intervalMs: 1, listPages: 2, credentialAttempts: 2, deadlineSeconds: 120 },
    priorCompileProofs: ["c", "d"].map(tag => ({ runId: `stage3-20260930${tag}`, journalSha256: tag.repeat(64), validSourceCount: 338 })),
  };
}

test("the dedicated inventory counts each typed route once and keeps the full valid-source obligation", () => {
  for (const branch of ["absent", "present"]) {
    const m = buildNativeManifest(nativeParams(branch));
    assert.equal(m.sendAuthorized, false);
    assert.equal(m.closureReady, false);
    assert.equal(new Set(m.rows.map(r => r.id)).size, m.rows.length);
    assert.equal(Object.values(m.counts.partitions).reduce((a,b) => a+b,0),m.counts.total);
    assert.equal(m.counts.total,m.rows.length);
    assert.equal(m.rows.filter(r => r.kind === "invalid-test").length,1);
    assert(m.rows.every(r => !r.request.origin.includes("identitytoolkit")));
    assert.equal(m.priorCompileProofs[0].validSourceCount,338);
    assert.equal(m.accountProof.status,"NO_CREATION");
  }
});

const { buildNativeSchedule } = await import("./storage-rules/management-native-schedule.mjs");
test("installed-before and after proofs enclose the single invalid attempt and precede restore", () => {
  const m=buildNativeManifest(nativeParams()),s=buildNativeSchedule(m);
  const ids=s.normal.flatMap(step=>step.ids);
  assert(ids.indexOf("before/deny/decision")<ids.indexOf("invalid/test"));
  assert(ids.indexOf("invalid/test")<ids.indexOf("after/release"));
  assert(ids.indexOf("after/deny/decision")<ids.indexOf("restore/guard"));
  assert.equal(s.allIds.length,m.rows.length);
  assert.equal(new Set(s.allIds).size,s.allIds.length);
  assert.equal(s.maximumRecoveryRuns,1);
  assert.equal(s.settleConsecutive,2);
  const altered=structuredClone(m);altered.rows.find(r=>r.id==="invalid/test").phase="recovery";
  assert.throws(()=>buildNativeSchedule(altered),/manifest/);
});
