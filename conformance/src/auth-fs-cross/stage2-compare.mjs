// The comparison of AUTH-FS-CROSS stage-2 rows: what a row says that production and fireemu can
// be held to, the classification of one row, and the fixture built from two production
// recordings. Times, counts of repeated requests, heartbeats and snapshots that change only
// metadata are not compared; the order of what a listener delivered and how it ended is.

import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

const collapse = (list) => list.filter((value, i) => i === 0 || value !== list[i - 1]);

/** A native stream in one step: per target, what it delivered; REMOVE causes; its end. */
export function nativeSummary(listener) {
  const targets = {};
  const removed = {};
  const push = (target, value) => {
    targets[target] = [...(targets[target] ?? []), value];
  };
  for (const event of listener.events ?? []) {
    if (event.kind === "documentChange") for (const t of event.targetIds) push(t, `n:${event.n}`);
    else if (event.kind === "documentDelete" || event.kind === "documentRemove")
      for (const t of event.removedTargetIds) push(t, event.kind);
    else if (event.kind === "targetChange" && event.type === "REMOVE")
      for (const t of event.targetIds) removed[t] = event.cause?.code ?? null;
  }
  for (const t of Object.keys(targets)) targets[t] = collapse(targets[t]);
  return {
    targets,
    removed,
    end: listener.end ? listener.end.code : null,
    endedBefore: Boolean(listener.endedBefore),
  };
}

/** An SDK listener in one step: the server-confirmed states it showed, and its error. */
export function sdkSummary(listener) {
  const out = [];
  for (const event of listener.events ?? []) {
    if (event.kind === "error") out.push(`error:${event.code}`);
    else if (event.kind === "snapshot" && !event.fromCache && !event.pending)
      out.push(`docs:${event.docs.map((d) => (d.exists ? d.n : "absent")).join(",")}`);
  }
  return collapse(out);
}

/** A client's own events in one step: whose token each call carried, and how commands ended. */
export function clientSummary(events) {
  const wire = [
    ...new Set(
      events.filter((e) => e.kind === "wire").map((e) => `${e.service} ${e.method} ${e.principal}`),
    ),
  ].toSorted();
  return {
    wire,
    results: events
      .filter((e) => e.kind === "result")
      .map(
        (e) => `${e.op}:${e.ok ? "ok" : e.code}${e.attempts === undefined ? "" : `:${e.attempts}`}`,
      ),
    settled: events
      .filter((e) => e.kind === "write-settled")
      .map((e) => `${e.writeId}:${e.ok ? "ok" : e.code}`),
    auth: collapse(events.filter((e) => e.kind === "auth").map((e) => String(e.uid))),
  };
}

function listenersSummary(listeners = {}) {
  return Object.fromEntries(
    Object.entries(listeners).map(([ref, listener]) => [
      ref,
      ref.startsWith("grpc-") ? nativeSummary(listener) : sdkSummary(listener),
    ]),
  );
}

function clientsSummary(clients = {}) {
  return Object.fromEntries(Object.entries(clients).map(([name, e]) => [name, clientSummary(e)]));
}

/**
 * What a recorded row says that is compared. `late` names the expiry probes whose timer was
 * late: such a row is indeterminate, never a different outcome.
 */
export function comparable(row) {
  const form = comparableForm(row);
  return row.capped ? { ...form, capped: row.capped } : form;
}

function comparableForm(row) {
  if (row.probes)
    return {
      probes: Object.fromEntries(
        row.probes.map((p) => [p.doc, { listeners: listenersSummary(p.listeners) }]),
      ),
      late: row.probes.filter((p) => !p.onTime).map((p) => p.doc),
    };
  if (row.docs) return { docs: row.docs };
  if (row.resumes) return { first: row.first, resumes: row.resumes };
  if (row.streams) return { streams: row.streams, listeners: row.listeners };
  return {
    ...(row.result ? { result: clientSummary([row.result]).results } : {}),
    listeners: listenersSummary(row.listeners),
    clients: clientsSummary(row.clients),
  };
}

/**
 * Rows with a part whose result is allowed to vary, with the values allowed there. Everything
 * outside those parts must still be equal; a value outside the set, on either side, is a
 * mismatch.
 */
export const NONDETERMINISTIC_ROWS = {
  "held/exp-plus-35-sdk": {
    reason:
      "The deleted tenant's SDK client keeps its expired token after its refresh fails and retries. Local runs once let the refusal reach the listener inside the probe's window; production gave nothing in all four recordings (v6 and v7), and so has fireemu since a strict stream closes on its own instead of removing its targets. The set is that one value.",
    parts: [
      ["probes", "afc2-tenant/t1-sdk", "listeners", "sdk-ten-t1/doc"],
      ["probes", "afc2-tenant/t1-sdk", "listeners", "sdk-ten-t1/query"],
    ],
    allowed: [[]],
  },
};

const at = (form, path) => path.reduce((value, key) => value?.[key], form);

/** A copy of `form` with each of `parts` replaced by a marker. */
function without(form, parts) {
  const copy = structuredClone(form);
  for (const path of parts) {
    const parent = at(copy, path.slice(0, -1));
    if (parent && path.at(-1) in parent) parent[path.at(-1)] = "<allowed to vary>";
  }
  return copy;
}

/**
 * One row's status from its production form(s) and fireemu's, all `comparable` forms. `row`
 * names the row for its allowance in `NONDETERMINISTIC_ROWS`.
 */
export function classifyStage2({ row, stale, production, alternative, fireemu }) {
  if (stale) return "STALE_FIXTURE";
  if (production === undefined) return "MISSING_FIXTURE";
  if (fireemu === undefined) return "MISSING";
  // A client's request cap refused something: the row shows the harness's limit, not behavior.
  if ([production, alternative, fireemu].some((form) => form?.capped?.length)) return "CAPPED";
  if ([production, alternative, fireemu].some((form) => form?.late?.length)) return "INDETERMINATE";
  const rule = NONDETERMINISTIC_ROWS[row];
  if (rule) {
    const forms = [production, alternative, fireemu].filter(
      (form) => form !== undefined && form !== null,
    );
    const allowed = (form) =>
      rule.parts.every((path) =>
        rule.allowed.some((value) => isDeepStrictEqual(at(form, path), value)),
      );
    if (!forms.every(allowed)) return "MISMATCH";
    const rest = forms.map((form) => without(form, rule.parts));
    return rest.every((form) => isDeepStrictEqual(form, rest[0]))
      ? "MATCH_NONDETERMINISTIC"
      : "MISMATCH";
  }
  // The two production recordings disagree: the row is decided by the owner (C9), not here.
  if (alternative !== undefined) return "INDETERMINATE";
  return isDeepStrictEqual(production, fireemu) ? "MATCH" : "MISMATCH";
}

/**
 * The fixture from two recordings of the same program and harness: each row's comparable form
 * of recording 1, with recording 2's where it differs, and recording 1's raw row as evidence.
 */
export function buildFixture({ recordings, metas, programDigest, harnessDigest }) {
  const [first, second] = recordings;
  if (!first || !second) throw new Error("a fixture needs two recordings");
  for (const meta of metas)
    if (meta.programDigest !== programDigest || meta.harness !== harnessDigest)
      throw new Error(`recording ${meta.recording} is of another program or harness`);
  const rows = {};
  const ids = [...new Set([...Object.keys(first.rows), ...Object.keys(second.rows)])].toSorted();
  for (const id of ids) {
    const row = first.rows[id];
    const other = second.rows[id] === undefined ? undefined : comparable(second.rows[id]);
    if (row === undefined) {
      // Only recording 2 has the row: nothing to hold fireemu to until both agree.
      rows[id] = {
        conditions: second.rows[id].conditions,
        production: null,
        second: other,
        raw: second.rows[id],
      };
      continue;
    }
    const one = comparable(row);
    rows[id] = {
      conditions: row.conditions,
      production: one,
      ...(other !== undefined && !isDeepStrictEqual(one, other) ? { second: other } : {}),
      ...(other === undefined ? { second: null } : {}),
      raw: row,
    };
  }
  return {
    version: 1,
    recordedAgainst: {
      target:
        "production Firestore (native gRPC Listen, Node Web SDK 12.18.0, browser Web SDK 12.18.0 over WebChannel) and the Identity Platform sandbox, end-user ID tokens",
      note: "Two recordings, one run each. Principal uids, tenants, the run id, the project and its number are placeholders. `second` holds recording 2's form of a row where it differed; `null` where recording 2 has no such row.",
    },
    programDigest,
    harnessDigest,
    // When each native stream ended, as evidence (rows do not compare it); status texts stay in
    // the private recordings.
    recordings: metas.map(({ recording, startedAt, sha }, i) => ({
      recording,
      startedAt,
      sha,
      streamEnds: Object.fromEntries(
        Object.entries(recordings[i].streamEnds ?? {}).map(([name, end]) => {
          if (end === null) return [name, null];
          const { details: _details, ...kept } = end;
          return [name, kept];
        }),
      ),
    })),
    rows,
  };
}

/**
 * The committed evidence of one stage-2 comparison: the harness that recorded production (its
 * commit and digests, from the fixture) and the fireemu artifact compared (its commit and
 * sha256) are bound apart, since a later harness commit may change only how a run stops. Only
 * passing rows are accepted, and the summary must be what the rows add up to.
 */
export function stage2Evidence({ comparison, fixtureText, artifactSha256, harnessCommit, fireemuCommit }) {
  for (const [name, commit] of [
    ["harness", harnessCommit],
    ["fireemu", fireemuCommit],
  ])
    if (!/^[0-9a-f]{40}$/.test(commit ?? "")) throw new Error(`${name} needs a full commit`);
  if (!/^[0-9a-f]{64}$/.test(artifactSha256 ?? "")) throw new Error("artifactSha256 is required");
  const counted = {};
  for (const { status } of comparison.rows) counted[status] = (counted[status] ?? 0) + 1;
  if (!isDeepStrictEqual(counted, comparison.summary))
    throw new Error("the summary does not match the rows");
  const failing = comparison.rows
    .filter(({ status }) => status !== "MATCH" && status !== "MATCH_NONDETERMINISTIC")
    .map(({ row }) => row);
  if (failing.length) throw new Error(`not passing: ${failing.join(", ")}`);
  const fixture = JSON.parse(fixtureText);
  return {
    kind: "auth-fs-cross-stage2-comparison-v1",
    harness: {
      commit: harnessCommit,
      digest: fixture.harnessDigest,
      programDigest: fixture.programDigest,
    },
    fireemu: { commit: fireemuCommit, artifactSha256 },
    fixtureSha256: createHash("sha256").update(fixtureText).digest("hex"),
    summary: comparison.summary,
    rows: comparison.rows.map(({ row, status }) => ({ row, status })),
  };
}
