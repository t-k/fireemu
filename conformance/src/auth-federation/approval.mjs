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
// The coordinator's envelope also needs the owner's delegation of envelope approvals
// (`調整役への委任（枠の承認）`, 2026-09-28).
//
// Revocations are read from every line in their normalized form (NFKC, lower case; pre-send
// review M1), wherever they stand in the ledger, and fail closed; approvals stay exact:
// - a line whose topic names the delegation (`調整役への委任`) and says revoked voids every
//   coordinator envelope;
// - a line that says revoked and names this digest or this commit (in full or by a prefix of
//   at least 8 hex digits) or the approving envelope's ID withdraws the approval, and so does a
//   revocation that names no digest, commit or envelope for a topic of this packet or of the
//   parent alone.
// A revoked version or envelope is not restored by a later approval: it needs a new digest or
// envelope ID.

const DATE_LINE = /^- \d{4}-\d{2}-\d{2} \| /;
const DELEGATE = "Claude（委任。オーナーの裁量の委任 2026-09-28）";
const BASIS = { date: "2026-09-28", subject: "調整役への委任（本番の送信）" };
const ENVELOPE_BASIS = { date: "2026-09-28", subject: "調整役への委任（枠の承認）" };
const MAX_DELEGATED_USD = 10;

/** A ledger text as revocations are compared: NFKC, lower case (pre-send review M1). */
export const norm = (text) => text.normalize("NFKC").toLowerCase();
/** The revocation constants, already in their normalized form. */
export const REVOCATION_TOKENS = ["revoked", "調整役への委任", "envelopeid="];
const [REVOKED, DELEGATION, ENVELOPE_ID] = REVOCATION_TOKENS;

/**
 * The revocations of a ledger: every line that says revoked, normalized, with its topic (the
 * column after a leading date, or the first column; the whole line when it has fewer than three
 * columns).
 */
function revocations(lines) {
  return lines
    .map(norm)
    .filter((text) => text.includes(REVOKED))
    .map((text) => {
      const cols = text
        .replace(/^\s*-\s*/, "")
        .split("|")
        .map((col) => col.trim());
      const topic =
        cols.length < 3 ? text : /^\d{4}-\d{2}-\d{2}$/.test(cols[0]) ? cols[1] : cols[0];
      return { text, topic };
    });
}

/** Whether a revocation withdraws the approval of `packet` at `digest` from `commit`. */
function withdraws({ text, topic }, { parent, packet, digest, commit, envelopeId }) {
  const hexes = text.match(/[0-9a-f]{8,}/g) ?? [];
  if (hexes.some((hex) => hex.length <= 64 && digest.startsWith(hex))) return true;
  if (hexes.some((hex) => hex.length <= 40 && commit.startsWith(hex))) return true;
  if (envelopeId && text.includes(norm(envelopeId))) return true;
  const specific = hexes.some((hex) => hex.length >= 40) || text.includes(ENVELOPE_ID);
  return !specific && (topic === norm(parent) || topic.startsWith(norm(`${parent} ${packet}`)));
}

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
  const revoked = revocations(lines);
  const ownerLine = ({ date, subject }) =>
    lines.some((line) => {
      const [lineDate = "", lineSubject = "", , decider = ""] = columns(line);
      return lineDate === date && lineSubject === subject && decider.trim().startsWith("オーナー");
    });
  // The owner's delegations the coordinator's envelope lines rest on, both unrevoked.
  const delegated =
    ownerLine(BASIS) &&
    ownerLine(ENVELOPE_BASIS) &&
    !revoked.some(({ topic }) => topic.includes(DELEGATION));
  for (const line of lines) {
    // A line that says revoked and would approve names this digest or its envelope ID, so the
    // revocation check below withdraws it.
    const [, subject = "", body = "", decider = ""] = columns(line);
    const owner = decider.trim().startsWith("オーナー");
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
  if (
    approval &&
    revoked.some((revocation) =>
      withdraws(revocation, { parent, packet, digest, commit, envelopeId: approval.envelopeId }),
    )
  ) {
    return undefined;
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
