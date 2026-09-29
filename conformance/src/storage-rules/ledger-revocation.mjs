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
// The words that revoke, on the normalized (NFKC, lower-cased) line: "revoke" (also revoked, revokes), "revocation", "withdraw" (also withdrawn, withdrawal)
// "rescind" and the Japanese 取消, 取り消(し/す), 撤回, 取り下げ, 中止 and 無効.
// The delegation rows carry prose of their own (中止, 無効 and 取り下げ occur in it), so a delegation is revoked only by the narrower set.
const DELEGATION_WORDS = /revoke|revocation|withdraw|取消|取り消|撤回/;
const REVOCATION_WORDS = /revoke|revocation|withdraw|rescind|取消|取り消|撤回|取り下げ|中止|無効/;
const PIN_PREFIX_LENGTH = 8;

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

export function rowSha256(line) {
  return createHash("sha256").update(line, "utf8").digest("hex");
}

// A pin a line may name as a key-bound field, and the token shapes that count as references to a version.
const KEYED = /(packetsha256|sourcecommit|runnersha256|manifestsha256|fixtureschemasha256|envelopeid)=([a-z0-9][a-z0-9._-]*)/g;
// A lane other than this one, named the way the ledger names lanes: the revocation of another lane is not a revocation of this one.
const OTHER_LANE = /(?<![a-z0-9-])(?:fs|auth|functions|storage|hosting|firestore|app-check)-[a-z][a-z0-9-]*/;
const HEX_REFERENCE = /(?<![0-9a-f])(?:[0-9a-f]{40}|[0-9a-f]{64})(?![0-9a-f])/g;

/**
 * Find ledger lines that stop this lane's approval or the coordinator's delegation.
 * The whole normalized line is read (position, column count and spelling do not matter). A line that contains a revocation word ("revoked", "revocation", "revoke", "取消", "取り消", "撤回", "withdrawn", "withdraw") and
 * names the lane at all (the task ID anywhere in it) stops the approval, unless it is a consumed revocation of an earlier
 * version: it does not name this version (no pin in full or by an 8-character prefix, no envelope ID), it carries at
 * least one key-bound field (packetSha256=..., sourceCommit=..., runnerSha256=..., manifestSha256=...,
 * fixtureSchemaSha256=..., envelopeId=...), every such field equals the same field of an earlier approval line of this lane in the
 * same ledger, and no other digest or commit appears in it. A line that names the coordinator delegation makes every
 * coordinator-written row unusable. A historical line that only mentions the words is ignored through an allowlist that
 * pins the exact raw line by SHA-256. Returns 1-based line numbers: `lane` (stops), `consumed` (skipped by the row
 * parsing as well) and `delegation`.
 */
export function scanRevocations({ ledgerText, taskId, pins, envelopeId, allowlist = HISTORICAL_REVOCATION_ALLOWLIST }) {
  const allowed = new Set(allowlist.map((entry) => entry.sha256));
  const taskKey = normalizeLedgerText(taskId);
  const packetKey = normalizeLedgerText(pins.packetSha256);
  const pinPrefixes = Object.values(pins).map((pin) => normalizeLedgerText(pin).slice(0, PIN_PREFIX_LENGTH));
  const envelopeKey = typeof envelopeId === "string" && envelopeId !== "" ? normalizeLedgerText(envelopeId) : null;
  const approved = new Set();
  const globalCandidates = [];
  let decisionLine = -1;
  const lane = [];
  const consumed = [];
  const delegation = [];
  ledgerText.split("\n").forEach((line, index) => {
    const text = normalizeLedgerText(line);
    const keyed = [...text.matchAll(KEYED)].map((match) => `${match[1]}=${match[2]}`);
    if (!REVOCATION_WORDS.test(text)) {
      // An earlier approval line of this lane: what it carries is what a later consumed revocation may cite.
      const subject = (line.split("|")[1] ?? "").trim();
      const approvalLine = text.includes(taskKey) && (text.includes("decision=approve") || normalizeLedgerText(subject).endsWith(" envelope"));
      if (approvalLine) keyed.forEach((entry) => approved.add(entry));
      if (text.includes(packetKey)) decisionLine = index + 1;
    } else if (!allowed.has(rowSha256(line))) {
      const namesLane = text.includes(taskKey) || withoutQualifiers(normalizeLedgerText(line.split("|")[1] ?? "")).includes(taskKey);
      const namesThisVersion = pinPrefixes.some((prefix) => text.includes(prefix)) || (envelopeKey !== null && text.includes(envelopeKey));
      const keyedValues = new Set(keyed.map((entry) => entry.slice(entry.indexOf("=") + 1)));
      const references = [...(text.match(HEX_REFERENCE) ?? []), ...(text.match(envelopeIdPattern(taskKey)) ?? [])];
      const wellFormed = keyed.length > 0 && keyed.every((entry) => approved.has(entry)) && references.every((reference) => keyedValues.has(reference));
      if (namesThisVersion || (namesLane && !wellFormed)) lane.push(index + 1);
      else if (namesLane) consumed.push(index + 1);
      const isDelegation = text.includes(NORMALIZED_DELEGATION_MARKER);
      if (isDelegation) { if (DELEGATION_WORDS.test(text)) delegation.push(index + 1); }
      // A revocation that names no lane at all (the whole sandbox program, an unscoped "all") is a candidate to stop this lane too.
      else if (!namesLane && !namesThisVersion && !OTHER_LANE.test(text)) globalCandidates.push(index + 1);
    }
  });
  // It counts only when it was written after this packet's decision: a decision written later supersedes an earlier global revocation.
  if (decisionLine !== -1) lane.push(...globalCandidates.filter((line) => line > decisionLine));
  return { lane, consumed, delegation };
}

function envelopeIdPattern(taskKey) {
  return new RegExp(`(?<![a-z0-9-])${taskKey.replace(/[^a-z0-9]/g, "\\$&")}-[a-z0-9][a-z0-9.-]*-\\d+(?![a-z0-9.-])`, "g");
}
