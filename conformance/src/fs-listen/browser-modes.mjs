// The two WebChannel transports of the browser recording. Forced long polling closes every
// backchannel response at once (`CI=1`); streaming turns the buffering-proxy detection off so the
// backchannel stays open and chunked (`CI=0`). This file imports nothing: the page loads it too.

export const MODES = ["long-polling", "streaming"];

export const MODE_SETTINGS = {
  "long-polling": { experimentalForceLongPolling: true },
  streaming: { experimentalForceLongPolling: false, experimentalAutoDetectLongPolling: false },
};

/** The `CI` value of a Listen channel request in each mode (what the wire evidence must show). */
export const EXPECTED_CI = { "long-polling": "1", streaming: "0" };

/** A short suffix per mode: the run id of a mode is the run id plus this. */
export const MODE_SUFFIX = { "long-polling": "l", streaming: "s" };

/** The run id of one mode of a recording. */
export const modeRun = (run, mode) => {
  const suffix = MODE_SUFFIX[mode];
  if (!suffix) throw new Error(`unknown browser transport mode: ${mode}`);
  return `${run}${suffix}`;
};

export const L3_IDS = ["201C", "201", "202", "203", "203C"];
export const L3_PHASES = {
  "201C": ["control-start", "control-end"],
  201: ["before-reload", "after-reload"],
  202: ["before-close", "replacement"],
  203: ["warm", "restarted-offline", "restarted-online"],
  "203C": ["cold-offline", "cold-online"],
};

/** Frozen completeness rules; latency and callback counts remain diagnostics. */
export function l3Problems(id, evidence) {
  const problems = [];
  const phases = Array.isArray(evidence?.phases) ? evidence.phases : [];
  const expected = L3_PHASES[id];
  if (!expected || phases.map((p) => p?.phase).join() !== expected.join())
    problems.push(
      id.startsWith("20") && ["203", "203C"].includes(id)
        ? "missing cache checkpoints"
        : "missing lifecycle checkpoints",
    );
  if (
    phases.some(
      (p) =>
        !p ||
        typeof p.phase !== "string" ||
        !Array.isArray(p.snapshots) ||
        !Array.isArray(p.errors),
    )
  )
    return [...problems, "malformed checkpoint"];
  const completeSet = (s) =>
    s?.fromCache === false &&
    s.hasPendingWrites === false &&
    Array.isArray(s.docs) &&
    s.docs.join() === "alpha,beta";
  for (const phase of phases) {
    if (
      !phase ||
      typeof phase.phase !== "string" ||
      !Array.isArray(phase.snapshots) ||
      !Array.isArray(phase.errors)
    ) {
      problems.push("malformed checkpoint");
      continue;
    }
    if (!Array.isArray(phase.failures) || phase.failures.length || phase.errors?.length)
      problems.push("phase failed");
    if (!phase.phase.endsWith("offline") && !completeSet(phase.snapshots?.at(-1)))
      problems.push("missing server-backed set");
  }
  if (["201", "202"].includes(id)) {
    if (
      !Array.isArray(evidence.markers) ||
      evidence.markers.join() !==
        (id === "201" ? "checkpoint,reload,server" : "checkpoint,close,new-tab,server")
    )
      problems.push("unordered lifecycle markers");
    if (!evidence.oldSession || !evidence.newSession || evidence.oldSession === evidence.newSession)
      problems.push("missing distinct channel sessions");
    if (
      !Array.isArray(evidence.terminate) ||
      !evidence.terminate.some(
        (e) => e?.dispatched && e.outcome === "completed" && e.status >= 200 && e.status < 300,
      )
    )
      problems.push("terminate not confirmed");
  }
  if (id === "201C" && evidence.uninterrupted !== true) problems.push("control interrupted");
  if (["203", "203C"].includes(id)) {
    const offline = phases.find((p) => typeof p?.phase === "string" && p.phase.endsWith("offline"));
    if (
      !offline ||
      offline.networkDisabled !== true ||
      offline.playwrightOffline !== true ||
      offline.enableCalls !== 0
    )
      problems.push("missing offline state");
    if (
      !Array.isArray(offline?.snapshots) ||
      offline.snapshots.length === 0 ||
      offline.snapshots.some((s) => s?.fromCache !== true || s.hasPendingWrites !== false)
    )
      problems.push("invalid offline metadata");
    if (phases.at(-1)?.enableCalls !== 1) problems.push("reconnect count");
    if (
      id === "203" &&
      (!evidence.sameProfile ||
        !evidence.processExited ||
        evidence.cacheMode !== "persistent" ||
        !Array.isArray(offline?.cacheRead?.docs) ||
        offline.cacheRead.docs.join() !== "alpha,beta" ||
        !Array.isArray(offline?.snapshots?.at(-1)?.docs) ||
        offline.snapshots.at(-1).docs.join() !== "alpha,beta")
    )
      problems.push("persistent restart not observed");
    if (id === "203C" && (evidence.cacheMode !== "memory" || !offline?.cacheRead))
      problems.push("cold read not observed");
    const required = id === "203" ? ["warm", "restarted-online"] : ["cold-online"];
    for (const phase of required) {
      const wire = Array.isArray(evidence.wire)
        ? evidence.wire.filter((e) => e?.phase === phase)
        : [];
      if (
        !wire.some((e) => e.targets?.length) ||
        !wire.some(
          (e) =>
            Array.isArray(e.boundaries) &&
            e.boundaries.some((b) => typeof b?.readTime === "string") &&
            e.boundaryComplete === true &&
            !e.overflow &&
            !e.decodeError &&
            e.status >= 200 &&
            e.status < 300,
        )
      )
        problems.push(`missing wire boundary: ${phase}`);
    }
  }
  return problems;
}
