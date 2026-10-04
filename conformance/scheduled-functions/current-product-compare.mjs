// Scoped replay of one saved calendar recording; this never issues a native certificate.
import { readFile } from "node:fs/promises";
import { CALENDAR_CASES } from "./calendar.mjs";
import { loadRecordedCalendarInputs } from "./calendar-recording.mjs";
import { prepareCalendarSession } from "./calendar-session.mjs";
import {
  calendarInstantNanos,
  exerciseCalendarSession,
  localCalendarClient,
} from "./calendar-local.mjs";

export function calendarRefusalDiagnostic(caseId) {
  if (caseId === "c07")
    return 'error: manifest: function "calendarProbe": time zone: unknown time zone "Invalid/Unknown"';
  if (caseId === "c08")
    return 'error: manifest: function "calendarProbe": schedule: unrecognised schedule "0 0 0 1 4 *"';
  throw new Error("unrecorded calendar startup refusal");
}

// The launcher supplies the daemon's loopback endpoints; the existing collector judges time.
export async function collectPreparedCalendar({ prepared, controlUrl, functionsHost, token }) {
  const { input, anchor } = JSON.parse(await readFile(prepared.inputPath, "utf8"));
  return exerciseCalendarSession({
    input,
    anchor,
    ...localCalendarClient({ controlUrl, functionsHost, token }),
  });
}

function sessionMatches(session, prepared, classification, caseId) {
  if (session?.timedOut !== false || session?.cancelled !== false) return false;
  const cleanup = session?.cleanup;
  if (
    !cleanup ||
    ![cleanup.survivors, cleanup.claims, cleanup.listeners].every(
      (rows) => Array.isArray(rows) && rows.length === 0,
    )
  )
    return false;
  if (JSON.stringify(session.identity) !== JSON.stringify(prepared.identity)) return false;
  if (classification === "observed-refusal")
    return session.exitCode === 1 && session.diagnostic === calendarRefusalDiagnostic(caseId);
  const callback = session.callback;
  try {
    return (
      session.exitCode === 0 &&
      callback?.matched === true &&
      callback.reason === null &&
      callback.anchor === prepared.identity.anchor &&
      callback.receipts?.length === 1 &&
      calendarInstantNanos(callback.receipts[0].scheduleTime) ===
        calendarInstantNanos(callback.scheduleTime)
    );
  } catch {
    return false;
  }
}

export async function compareRecordedCalendar({ recording, artifact, executeSession, save }) {
  if (typeof executeSession !== "function" || typeof save !== "function")
    throw new Error("an owned launcher and durable result sink are required");
  const admitted = await loadRecordedCalendarInputs(recording);
  const binding = {
    sourceCommit: artifact.sourceCommit,
    binarySha256: artifact.binarySha256,
    runnerSha256: artifact.runnerSha256,
    sourceRoot: artifact.root,
    fixtureRoot: artifact.fixtureRoot ?? artifact.root,
  };
  const rows = [];
  for (const proof of admitted.cases) {
    const item = CALENDAR_CASES.find(({ id }) => id === proof.caseId);
    const row = {
      caseId: item.id,
      conditionId: item.conditionId,
      case: item.case,
      classification: proof.classification,
      recording: { ...admitted.pins, bodySha256: proof.bodySha256 },
      artifact: { ...binding },
      sessions: [],
      status: "NEEDS_REVIEW",
      // Endpoint agreement is stronger than the original creation-time bracket criterion.
      productionGap: "UNKNOWN",
    };
    if (
      proof.classification === "accepted" ||
      (proof.classification === "observed-refusal" &&
        proof.status === 400 &&
        ["c07", "c08"].includes(item.id))
    ) {
      const anchors =
        proof.classification === "accepted" ? proof.input.anchors : [proof.anchors[0]];
      for (const anchor of anchors) {
        const input = proof.input ?? {
          caseId: item.id,
          schedule: item.schedule,
          timeZone: item.timeZone,
          scheduleTime: anchor,
        };
        const prepared = await prepareCalendarSession({
          ...artifact,
          root: binding.fixtureRoot,
          input,
          anchor,
        });
        const session = await executeSession({ prepared, classification: proof.classification });
        row.sessions.push({
          prepared,
          result: session,
          matched:
            sessionMatches(session, prepared, proof.classification, item.id) &&
            (proof.classification !== "accepted" ||
              session.callback.scheduleTime === proof.input.scheduleTime),
        });
      }
      if (row.sessions.every(({ matched }) => matched)) row.status = "MATCH";
    }
    await save(row);
    rows.push(row);
  }
  const matches = rows.filter(({ status }) => status === "MATCH");
  return {
    schemaVersion: 1,
    recordingCount: 1,
    artifact: { ...binding },
    matched: matches.length,
    acceptedMatched: matches.filter(({ classification }) => classification === "accepted").length,
    refusalMatched: matches.filter(({ classification }) => classification === "observed-refusal")
      .length,
    needsReview: rows.length - matches.length,
    acceptedAnchorRule: "both-recorded-endpoints",
    productionGap: "UNKNOWN",
    fullClosure: false,
    nativeCertificateIssued: false,
    rows,
  };
}
