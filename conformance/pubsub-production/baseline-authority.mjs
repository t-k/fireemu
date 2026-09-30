// Isolated fixed read-only baseline authority; never authorizes an arbitrary POST or writer.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { DELEGATION_SUBJECTS, scanRevocations } from "./ledger-revocation.mjs";
const PROJECT = "fireemu-oracle-idp";
const COORDINATOR = "Claude（委任。枠の内の承認し直し）";
const ENVELOPE_ACTOR = "Claude（委任。オーナーの裁量の委任 2026-09-28）";
function row(line) {
  const columns = line.split("|").map((s) => s.trim());
  if (columns.length !== 5) throw new Error("invalid authoritative ledger row");
  const fields = {};
  for (const part of columns[2].split(";")) {
    if (!part.trim()) continue;
    const at = part.indexOf("=");
    const key = part.slice(0, at).trim(),
      value = part.slice(at + 1).trim();
    if (at < 1 || !value || Object.hasOwn(fields, key))
      throw new Error("invalid or duplicate ledger field");
    fields[key] = value;
  }
  return { subject: columns[1], fields, actor: columns[3] };
}
export function assertBaselineAuthority({
  ledgerText,
  decisionLine,
  pins,
  envelopeId,
  subject,
  maxRequests,
  reserveUsd,
}) {
  if (
    subject !== "PUBSUB-EVENTARC fixture-baseline-001" ||
    envelopeId !== "PUBSUB-EVENTARC-fixture-baseline-001" ||
    maxRequests !== 3 ||
    reserveUsd !== 0.01
  )
    throw new Error("fixed baseline scope required");
  const requiredPins = ["packetSha256", "manifestSha256", "runnerSha256", "sourceCommit"];
  if (
    !pins ||
    Object.getPrototypeOf(pins) !== Object.prototype ||
    Object.keys(pins).length !== requiredPins.length ||
    !requiredPins.every(
      (key) =>
        typeof pins[key] === "string" &&
        new RegExp(`^[a-f0-9]{${key === "sourceCommit" ? 40 : 64}}$`).test(pins[key]),
    )
  )
    throw new Error("closed baseline version pins required");
  const lines = ledgerText.split("\n");
  if (!Number.isInteger(decisionLine) || decisionLine < 1 || decisionLine > lines.length)
    throw new Error("owner version line required");
  const decision = row(lines[decisionLine - 1]);
  if (
    decision.subject !== subject ||
    !lines[decisionLine - 1].split("|")[2].trim().startsWith("decision=APPROVE;") ||
    decision.fields.decision !== "APPROVE" ||
    !Object.entries({ ...pins, envelopeId }).every(([k, v]) => decision.fields[k] === v)
  )
    throw new Error("version binding mismatch");
  if (decision.actor !== COORDINATOR && !decision.actor.startsWith("オーナー"))
    throw new Error("owner or delegated coordinator required");
  const revocations = scanRevocations({ ledgerText, taskId: "PUBSUB-EVENTARC", pins, envelopeId });
  if (
    revocations.lane.length ||
    revocations.delegation.length ||
    revocations.global.some((line) => line > decisionLine)
  )
    throw new Error("baseline authority revoked or globally stopped");
  const envelopes = lines
    .slice(0, decisionLine - 1)
    .flatMap((line) => (line.split("|")[1]?.trim() === `${subject} envelope` ? [row(line)] : []))
    .filter((r) => r.fields.envelopeId === envelopeId);
  if (envelopes.length !== 1) throw new Error("one preceding bounded envelope required");
  const envelope = envelopes[0];
  const requestCap = Number(envelope.fields.maxRequests),
    cost = Number(envelope.fields.reserveUsd);
  if (
    envelope.fields.project !== PROJECT ||
    !Number.isSafeInteger(requestCap) ||
    requestCap !== maxRequests ||
    envelope.fields.maxCredentialCliInvocations !== "1" ||
    envelope.fields.maxWallSeconds !== "600" ||
    envelope.fields.readScope !== "project-identity-project-policy-pubsub-service-account" ||
    !Number.isFinite(cost) ||
    cost < reserveUsd ||
    cost > 10 ||
    envelope.fields.writes !== "none" ||
    envelope.fields.iamConfig !== "none" ||
    envelope.fields.retries !== "none"
  )
    throw new Error("baseline exceeds read-only envelope");
  if (envelope.actor === ENVELOPE_ACTOR) {
    if (envelope.fields["根拠"] !== `2026-09-28 ${DELEGATION_SUBJECTS.send}`)
      throw new Error("delegated envelope provenance required");
  } else if (!envelope.actor.startsWith("オーナー")) throw new Error("unauthorized envelope actor");
  if (decision.actor === COORDINATOR || envelope.actor === ENVELOPE_ACTOR) {
    for (const delegationSubject of Object.values(DELEGATION_SUBJECTS)) {
      const matches = lines.filter((line) => line.split("|")[1]?.trim() === delegationSubject);
      if (matches.length !== 1) throw new Error("one owner delegation required");
      const grant = matches[0].split("|").map((column) => column.trim());
      if (
        grant.length !== 5 ||
        !grant[2].startsWith("decision=APPROVE;") ||
        [...grant[2].matchAll(/(?:^|;\s*)decision\s*=/g)].length !== 1 ||
        !grant[3].startsWith("オーナー")
      )
        throw new Error("owner delegation missing");
    }
  }
  return { decisionLine, envelopeId };
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    process.stdout.write(
      JSON.stringify(assertBaselineAuthority(JSON.parse(readFileSync(0, "utf8")))) + "\n",
    );
  } catch {
    process.stderr.write("Baseline authority refused.\n");
    process.exitCode = 1;
  }
}
