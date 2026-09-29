import { copyProductionCaptureRecord } from "./production-capture-input.mjs";
import {
  originalProductionArtifactContext,
  productionArtifactProfileUsesPlan,
} from "./production-artifact-policy.mjs";
import { originalProductionStage3CounterSnapshot } from "./request-counter.mjs";
import {
  productionStandaloneUsesArtifactProfile,
  failStopProductionPrivacy,
} from "./production-standalone-fail-stop.mjs";

const projections = new WeakMap(),
  receipts = new WeakMap();
const now = Date.now.bind(Date),
  Instant = Date;
const pinKeys = ["sourceCommit", "packetSha256", "planSha256", "rulesSourceSha256", "corpusSha256"];
/** Fixed source inputs are configuration; no observation bytes or clock/count callbacks are accepted. */
export function createProductionSharedRecordProjection(supplied) {
  try {
    const input = copyProductionCaptureRecord(supplied, [
      "profile",
      "boundary",
      "counter",
      "plan",
      "pins",
    ]);
    if (
      Object.keys(input).length !== 5 ||
      !productionArtifactProfileUsesPlan(input.profile, input.plan) ||
      !productionStandaloneUsesArtifactProfile(input.boundary, input.profile) ||
      !originalProductionStage3CounterSnapshot(input.counter, input.profile)
    )
      throw new Error();
    const pins = copyProductionCaptureRecord(input.pins, pinKeys);
    if (
      Object.keys(pins).length !== pinKeys.length ||
      pinKeys.some(
        (key) =>
          typeof pins[key] !== "string" ||
          !(key === "sourceCommit" ? /^[a-f0-9]{40}$/ : /^[a-f0-9]{64}$/).test(pins[key]),
      ) ||
      pins.rulesSourceSha256 !== input.plan.rulesSourceSha256
    )
      throw new Error();
    const projection = Object.freeze({});
    projections.set(projection, {
      ...input,
      pins: Object.freeze(pins),
      projectId: input.plan.projectId,
      runtime: originalProductionArtifactContext(input.profile),
    });
    return projection;
  } catch {
    throw new Error("invalid production shared record projection");
  }
}
/** Candidates prove closed serialization only, never durability, approval or semantic cleanup. */
export function copyProductionSharedRecordBytes(receipt, projection) {
  const binding = receipts.get(receipt);
  return projections.has(projection) && binding?.projection === projection
    ? Buffer.from(binding.bytes)
    : null;
}
/** Final serialized bytes include the line suffix; source-only privacy failures stop synchronously. */
export function buildProductionSharedRecord(projection, supplied) {
  const source = projections.get(projection);
  if (!source) throw new Error("invalid production shared record projection");
  let recording = 1,
    reason = "shared-record-uncheckable";
  try {
    const snapshot = originalProductionStage3CounterSnapshot(source.counter, source.profile);
    if (!snapshot) throw new Error();
    recording = snapshot.recording;
    const row = copyProductionCaptureRecord(supplied, ["recording", "kind", "outcome"]);
    if (
      Object.keys(row).length !== 3 ||
      row.recording !== recording ||
      !["started", "terminal", "configuration-change"].includes(row.kind) ||
      !["STARTED", "LOCAL_COMPLETE", "BLOCKED", "NEEDS_RECOVERY", "CONFIGURATION_CHANGED"].includes(
        row.outcome,
      )
    )
      throw new Error();
    if (
      row.kind === "started"
        ? row.outcome !== "STARTED" || !snapshot.startAttempted
        : row.kind === "configuration-change"
          ? recording !== 2 || row.outcome !== "CONFIGURATION_CHANGED"
          : !["LOCAL_COMPLETE", "BLOCKED", "NEEDS_RECOVERY"].includes(row.outcome)
    )
      throw new Error();
    if (
      row.outcome === "LOCAL_COMPLETE" &&
      (snapshot.activeRecipeId ||
        snapshot.completedRecipes?.[recording - 1] !== 26 ||
        !["cleanup", "closed"].includes(snapshot.mode) ||
        snapshot.busy ||
        snapshot.admissionFailed)
    )
      throw new Error();
    const counts = snapshot.recordings[recording - 1];
    const value = {
      type: "production-shared-record",
      kind: row.kind,
      lane: "codex-lane2",
      projectId: source.projectId,
      recording,
      runId: source.runtime.runIds[recording - 1],
      outcome: row.outcome,
      requests: snapshot.total,
      subject: counts.subject,
      cleanup: counts.cleanup,
      timestamp: new Instant(now()).toISOString(),
      ...source.pins,
    };
    const bytes = Buffer.from(JSON.stringify(value) + "\n");
    if (source.runtime.secretRegistry.openScan().hasSecretCopy(bytes.toString("utf8"))) {
      reason = "shared-record-withheld-privacy";
      throw new Error();
    }
    const receipt = Object.freeze({ type: "production-shared-record-candidate", recording });
    receipts.set(receipt, { projection, bytes });
    return receipt;
  } catch {
    failStopProductionPrivacy(source.boundary, { recording, reason });
  }
}
