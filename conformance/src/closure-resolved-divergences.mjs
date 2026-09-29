// A documented divergence recorded on a lane artifact can later be resolved on an integrated
// release artifact. A closure then lists it under a condition's `evidence.resolvedDivergences`,
// and a lane comparison may keep that row as non-MATCH only while the integrated comparison the
// entry binds by digest, produced by the closure's integrated release binary, shows the row MATCH.
// Every other non-MATCH row still needs a current documented divergence.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

/**
 * The rows a closure records as resolved, after checking each entry against its evidence.
 * `readFile(path)` returns the bytes of a repository-relative path.
 */
export function resolvedDivergenceRows(closure, readFile) {
  const rows = new Set();
  const binary = closure.integratedRegression?.releaseBinarySha256;
  for (const condition of closure.conditions) {
    for (const entry of condition.evidence?.resolvedDivergences ?? []) {
      const label = `${condition.conditionId}: resolved ${entry.row}`;
      assert.ok(entry.decidedBy && entry.scopeDecision && entry.resolvedOn, label);
      assert.match(entry.resolvedArtifactSha256 ?? "", /^[0-9a-f]{64}$/, label);
      assert.equal(
        entry.resolvedArtifactSha256,
        binary,
        `${label}: on the integrated release binary`,
      );
      const evidence = entry.resolvedEvidence;
      assert.equal(evidence?.status, "MATCH", label);
      const bytes = readFile(evidence.path);
      assert.equal(createHash("sha256").update(bytes).digest("hex"), evidence.sha256, label);
      const comparison = JSON.parse(bytes.toString("utf8"));
      assert.equal(comparison.artifactSha256, entry.resolvedArtifactSha256, label);
      const row = comparison.rows.find(({ row: id }) => id === entry.row);
      assert.equal(row?.status, "MATCH", `${label}: matches in the integrated comparison`);
      rows.add(entry.row);
    }
  }
  return rows;
}
