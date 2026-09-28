// Approvals of a production packet in the owner ledger (owner decisions of 2026-09-27 and
// C, 2026-09-28). A packet at a digest is approved by either
// (1) the owner's line for that version:
//     `- YYYY-MM-DD | <parent> | … <packet> APPROVED <digest> … | オーナー… | …`, or
// (2) the owner's envelope line and the coordinator's line approving that version inside it:
//     `- YYYY-MM-DD | <parent> <packet> envelope | envelopeId=…; project=…; maxRequests=…;
//      reserveUsd=…; … | オーナー… | …`
//     `- YYYY-MM-DD | <parent> <packet> | decision=APPROVE; envelopeId=…; packetSha256=<digest>;
//      sourceCommit=<commit>; … | Claude（委任… | …`
// The envelope must cover the runner: the same project and limits no lower than the runner's.
// Under the owner's delegation (addendum of 2026-09-28, 「委任も (イ)で」), the envelope line may
// also be the coordinator's: its decider exactly `Claude（委任。オーナーの裁量の委任 2026-09-28）`,
// its body naming `根拠=2026-09-28 調整役への委任（本番の送信）`, that basis line present in the
// ledger by the owner, and a reserve of at most US$10.
// A later line of the parent and packet saying REVOKED with the digest or the envelope ID
// withdraws what it names.

const DATE_LINE = /^- \d{4}-\d{2}-\d{2} \| /;
const DELEGATE = "Claude（委任。オーナーの裁量の委任 2026-09-28）";
const BASIS = { date: "2026-09-28", subject: "調整役への委任（本番の送信）" };
const MAX_DELEGATED_USD = 10;

const escapeRegExp = (text) => text.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** The ` | `-separated columns of a dated ledger line, without the leading `- `. */
function columns(line) {
  return DATE_LINE.test(line) ? line.slice(2).split(" | ") : [];
}

/** `key=value; key=value` as an object (values trimmed, the last of a repeated key wins). */
export function fields(text) {
  return Object.fromEntries(
    text
      .split(";")
      .map((part) => part.trim())
      .filter((part) => part.includes("="))
      .map((part) => [
        part.slice(0, part.indexOf("=")).trim(),
        part.slice(part.indexOf("=") + 1).trim(),
      ]),
  );
}

/**
 * The approval of `packet` of `parent` at `digest` (64 hex digits) built from `commit`, or
 * undefined. `runner` is `{project, maxRequests, reserveUsd}`, the runner's own constants an
 * envelope must cover. Returns `{kind: "owner" | "envelope", line, envelopeId?}`.
 */
export function packetApproval(ownerDecisions, { parent, packet, digest, commit, runner }) {
  if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error("a digest is 64 hex digits");
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error("a commit is 40 hex digits");
  const word = (verb) =>
    new RegExp(`(?:^|[^\\w-])${escapeRegExp(packet)} ${verb} ${digest}(?![0-9A-Za-z])`);
  const envelopes = new Map();
  let approval;
  const lines = ownerDecisions.split("\n");
  // The owner's delegation the coordinator's envelope lines rest on.
  const delegated = lines.some((line) => {
    const [date = "", subject = "", , decider = ""] = columns(line);
    return (
      date === BASIS.date && subject === BASIS.subject && decider.trim().startsWith("オーナー")
    );
  });
  for (const line of lines) {
    const [, subject = "", body = "", decider = ""] = columns(line);
    const owner = decider.trim().startsWith("オーナー");
    const ours = subject === `${parent} ${packet}` || subject === `${parent} ${packet} envelope`;
    // Revocations: of this version, or of the envelope it was approved in.
    if ((ours || subject === parent) && /\bREVOKED\b/.test(body)) {
      const id = /\benvelopeId=([A-Za-z0-9_-]+)/.exec(body)?.[1];
      if (body.includes(digest)) approval = undefined;
      if (id) {
        envelopes.delete(id);
        if (approval?.envelopeId === id) approval = undefined;
      }
      continue;
    }
    if (subject === parent && owner && word("APPROVED").test(body)) {
      approval = { kind: "owner", line };
    } else if (subject === `${parent} ${packet} envelope` && owner) {
      const envelope = fields(body);
      if (envelope.envelopeId) envelopes.set(envelope.envelopeId, envelope);
    } else if (
      subject === `${parent} ${packet} envelope` &&
      delegated &&
      decider.trim() === DELEGATE
    ) {
      const envelope = fields(body);
      const reserve = /^\d+(\.\d+)?$/.test(envelope.reserveUsd ?? "")
        ? Number(envelope.reserveUsd)
        : Number.NaN;
      if (
        envelope.envelopeId &&
        envelope["根拠"] === `${BASIS.date} ${BASIS.subject}` &&
        reserve <= MAX_DELEGATED_USD
      ) {
        envelopes.set(envelope.envelopeId, envelope);
      }
    } else if (subject === `${parent} ${packet}` && decider.trim().startsWith("Claude（委任")) {
      const version = fields(body);
      const envelope = envelopes.get(version.envelopeId);
      if (
        version.decision === "APPROVE" &&
        version.packetSha256 === digest &&
        version.sourceCommit === commit &&
        envelope &&
        covers(envelope, runner)
      ) {
        approval = { kind: "envelope", line, envelopeId: version.envelopeId };
      }
    }
  }
  return approval;
}

/** Whether an envelope covers the runner: the same project, limits at least the runner's. */
export function covers(envelope, runner) {
  const number = (value) => (/^\d+(\.\d+)?$/.test(value ?? "") ? Number(value) : Number.NaN);
  return (
    envelope.project === runner.project &&
    number(envelope.maxRequests) >= runner.maxRequests &&
    number(envelope.reserveUsd) >= runner.reserveUsd
  );
}
