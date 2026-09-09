import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  classifyProductionCase,
  summarizeStatuses,
  validateEvidenceJoin,
  validateRecordedExpectation,
  validateLiveEvidence,
} from "./evidence.mjs";

const completeEvidence = () => ({
  observation: { mode: "live", database: { target: "local" } },
  source: { gitSha: "a".repeat(40), trackedTreeClean: true },
  package: {
    version: "0.1.0",
    manifestDigest: "package-digest",
    integrity: "sha512-package",
  },
  artifact: { sha256: "binary-digest", platform: "darwin-arm64" },
  runtime: {
    profile: "emulator",
    configDigest: "config-digest",
    rulesDigest: "rules-digest",
  },
  inputs: {
    sdkLockDigest: "lock-digest",
    corpusDigest: "corpus-digest",
    indexDigest: "index-digest",
  },
});

describe("production evidence identity", () => {
  it("joins complete matching identities", () => {
    const result = validateEvidenceJoin(completeEvidence(), completeEvidence());
    assert.deepEqual(result, { verified: true, mismatches: [] });
  });

  it("refuses a changed binary, config, index or corpus identity", () => {
    const fields = [
      ["artifact", "sha256", "changed-binary"],
      ["runtime", "configDigest", "changed-config"],
      ["inputs", "indexDigest", "changed-index"],
      ["inputs", "corpusDigest", "changed-corpus"],
    ];
    for (const [section, field, value] of fields) {
      const actual = completeEvidence();
      actual[section][field] = value;
      const result = validateEvidenceJoin(completeEvidence(), actual);
      assert.equal(result.verified, false);
      const identityField =
        section === "artifact" ? "artifactSha256" : section === "runtime" ? "configDigest" : field;
      assert.match(result.mismatches[0], new RegExp(`^${identityField}:`));
    }
  });

  it("refuses stored expectations as live actual evidence", () => {
    const stored = completeEvidence();
    stored.observation.mode = "stored";
    assert.equal(validateLiveEvidence(stored).verified, false);
    assert.ok(
      validateLiveEvidence(stored).errors.includes("observation: live observation required"),
    );
  });

  it("refuses a changed stored corpus identity", () => {
    const actual = completeEvidence();
    const recorded = {
      sourceSha: actual.source.gitSha,
      corpusDigest: "old-corpus",
      sdkLockDigest: actual.inputs.sdkLockDigest,
      indexDigest: actual.inputs.indexDigest,
    };
    const result = validateRecordedExpectation(recorded, actual, { requireIndex: true });
    assert.deepEqual(result, {
      verified: false,
      mismatches: ["corpusDigest: old-corpus != corpus-digest"],
    });
  });

  it("keeps local-only and index-required rows explicit", () => {
    const values = { production: "p", emulator: "e", fireemu: "p" };
    assert.equal(classifyProductionCase({ ...values, localOnly: true }), "excluded-local-only");
    assert.equal(classifyProductionCase({ ...values, needsIndex: true }), "production-needs-index");
  });

  it("refuses to classify missing production or fireemu observations as compatibility", () => {
    const missing = { missing: true };
    assert.equal(
      classifyProductionCase({ production: missing, emulator: "e", fireemu: missing }),
      "unverified",
    );
    assert.equal(
      classifyProductionCase({ production: missing, emulator: "e", fireemu: "f" }),
      "unverified",
    );
    assert.equal(
      classifyProductionCase({ production: "p", emulator: "e", fireemu: missing }),
      "unverified",
    );
    assert.equal(
      classifyProductionCase({ production: missing, emulator: missing, fireemu: missing }),
      "unverified",
    );
  });

  it("keeps transport failures unverified even when both sides fail identically", () => {
    for (const failed of [
      { status: 0, code: "no-response" },
      { status: 0, code: "probe-error" },
    ]) {
      const ok = { status: 200, code: "OK" };
      for (const observations of [
        { production: failed, emulator: ok, fireemu: ok },
        { production: ok, emulator: ok, fireemu: failed },
        { production: failed, emulator: failed, fireemu: failed },
      ]) {
        assert.equal(classifyProductionCase(observations), "unverified");
      }
    }
  });

  it("summarizes statuses without producing a compatibility percentage", () => {
    const summary = summarizeStatuses(["parity", "parity", "unverified"]);
    assert.deepEqual(summary, { parity: 2, unverified: 1 });
    assert.equal(Object.hasOwn(summary, "percentage"), false);
  });
});
