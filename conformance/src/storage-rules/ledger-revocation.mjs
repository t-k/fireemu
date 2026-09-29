import { createHash } from "node:crypto";

/** Delegation ledger subjects, spelled exactly as the owner ledger records them. */
export const DELEGATION_SUBJECTS = Object.freeze({
  send: "調整役への委任（本番の送信）",
  envelope: "調整役への委任（枠の承認）",
});

/** Comparison form used for every revocation check: NFKC, then lower case. */
export function normalizeLedgerText(text) {
  return text.normalize("NFKC").toLowerCase();
}

export const NORMALIZED_DELEGATION_MARKER = normalizeLedgerText("調整役への委任");
const REVOKED = "revoked";
const COMMIT_PREFIX_LENGTH = 8;

/**
 * Ledger rows that mention the lane and the word "revoked" without revoking anything.
 * Each entry pins one raw ledger line by SHA-256 and states why the line is harmless.
 */
export const HISTORICAL_REVOCATION_ALLOWLIST = Object.freeze([
  Object.freeze({
    sha256: "4d243d246c4b0da66512f691631c8d1b09111ef9e7364db3fb3efffa3b6e447d",
    reason: "2026-09-27 credential fixture row; the word describes a validSince-revoked test user, not a revocation of an approval",
  }),
]);

/** Drop parenthetical qualifiers such as "（訂正）", wherever they sit, from a normalized subject column. */
function withoutQualifiers(text) {
  let current = text.trim();
  for (;;) {
    const next = current.replace(/\s*\([^()]*\)/, "");
    if (next === current) return current;
    current = next;
  }
}

/** True when the text carries at least one whole 64-digit hex digest and none of them is one of this packet's pins. */
function onlyForeignDigests(text, pinKeys) {
  const digests = text.match(/(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])/g) ?? [];
  return digests.length > 0 && digests.every((digest) => !pinKeys.has(digest));
}

export function rowSha256(line) {
  return createHash("sha256").update(line, "utf8").digest("hex");
}

/**
 * Find ledger lines that stop this lane's approval or the coordinator's delegation.
 * A line counts when its normalized text contains "revoked" and names the lane subject, the lane
 * as a whole, the packet SHA, the source commit (full or at least eight digits) or the envelope ID;
 * or when it names the coordinator delegation. A row that names the lane but carries only whole digests
 * that belong to no pin of this packet is a consumed revocation of another version and does not count. A parenthetical qualifier on the subject
 * column, such as "（訂正）", does not hide the lane. Position, column count and spelling do not matter.
 * Returns 1-based line numbers.
 */
export function scanRevocations({ ledgerText, taskId, subject, packetSha256, sourceCommit, envelopeId, pinSha256s = [], allowlist = HISTORICAL_REVOCATION_ALLOWLIST }) {
  const allowed = new Set(allowlist.map((entry) => entry.sha256));
  const subjectKey = normalizeLedgerText(subject);
  const taskKey = normalizeLedgerText(taskId);
  const packetKey = normalizeLedgerText(packetSha256);
  const commitKey = normalizeLedgerText(sourceCommit).slice(0, COMMIT_PREFIX_LENGTH);
  const envelopeKey = typeof envelopeId === "string" && envelopeId !== "" ? normalizeLedgerText(envelopeId) : null;
  const pinKeys = new Set([packetKey, ...pinSha256s.map(normalizeLedgerText)]);
  const lane = [];
  const delegation = [];
  ledgerText.split("\n").forEach((line, index) => {
    const text = normalizeLedgerText(line);
    if (!text.includes(REVOKED) || allowed.has(rowSha256(line))) return;
    const subjectColumn = withoutQualifiers(normalizeLedgerText(line.split("|")[1] ?? ""));
    const namesThisVersion = text.includes(packetKey) || text.includes(commitKey) || (envelopeKey !== null && text.includes(envelopeKey));
    const namesLane = text.includes(subjectKey) || subjectColumn === taskKey;
    if (namesThisVersion || (namesLane && !onlyForeignDigests(text, pinKeys))) lane.push(index + 1);
    if (text.includes(NORMALIZED_DELEGATION_MARKER)) delegation.push(index + 1);
  });
  return { lane, delegation };
}
