// What a finished recording shows, case by case. This judge does not compare production with the local daemon (no
// production observation exists yet): it joins what the run sent with what Cloud Logging returned, so that a later
// comparison reads one record per case, and it reports what cannot be trusted: a delivery nobody asked for, a delivery
// of a task whose create was refused, an accepted task that never arrived, a create whose answer is unknown.
// Times are milliseconds from the moment the createTask request was dispatched, never wall clock.
import { runMarker } from "../plan.mjs";
import { isNotDelivered } from "../corpus.mjs";

const PLACEHOLDER_NUMBER = "123456789012";

/** `text` without the project number (a service account name carries it), which never reaches a published record. */
export const maskNumber = (text, projectNumber) =>
  projectNumber ? String(text).replaceAll(String(projectNumber), PLACEHOLDER_NUMBER) : String(text);

const atMs = (text) => {
  const ms = Date.parse(text ?? "");
  return Number.isFinite(ms) ? ms : null;
};

/** The deliveries of a case, from the `start` and `end` frames: one per (retry count, start time), with its end if it printed one. */
export function deliveriesOf(frames) {
  const starts = frames
    .filter(({ frame }) => frame.kind === "start")
    .map(({ frame, timestamp }) => ({ frame, timestamp }))
    .toSorted((a, b) => (atMs(a.frame.at) ?? 0) - (atMs(b.frame.at) ?? 0));
  const ends = frames.filter(({ frame }) => frame.kind === "end").map(({ frame }) => frame);
  return starts.map(({ frame }) => {
    const end = ends.find(
      (e) => e.startedAt === frame.at && e.retryCount === (frame.context?.retryCount ?? null),
    );
    return {
      retryCount: frame.context?.retryCount ?? null,
      startedAt: frame.at,
      endedAt: end?.at ?? null,
      context: frame.context,
      request: frame.request,
      step: frame.step ?? null,
    };
  });
}

/**
 * `program` is the run's record of what it sent, by case key: `{kind, sent, class, status, dispatchedAt, answeredAt,
 * answer}`. `frames` are the parsed log frames (`{insertId, timestamp, frame}`) and `errors` the ERROR entries.
 */
export function judge({ runId, program, frames, errors = [], projectNumber = null }) {
  const marker = runMarker(runId);
  const cases = {};
  const findings = [];
  const byCase = new Map();
  for (const entry of frames) {
    if (entry.frame.run !== marker) {
      findings.push({
        kind: "foreign-frame",
        function: entry.frame.function,
        run: entry.frame.run ?? null,
      });
      continue;
    }
    const list = byCase.get(entry.frame.case) ?? [];
    list.push(entry);
    byCase.set(entry.frame.case, list);
  }
  for (const key of byCase.keys())
    if (!(key in program)) findings.push({ kind: "frame-for-unknown-case", case: key });
  for (const [key, step] of Object.entries(program)) {
    const dispatched = step.dispatchedAt ?? null;
    const record = {
      kind: step.kind,
      sent: step.sent === true,
      class: step.class ?? null,
      status: step.status ?? null,
    };
    if (step.kind === "create" && step.sent === true) {
      const deliveries = deliveriesOf(byCase.get(key) ?? []).map((d) => ({
        ...d,
        startMs:
          atMs(d.startedAt) !== null && dispatched !== null ? atMs(d.startedAt) - dispatched : null,
        endMs:
          atMs(d.endedAt) !== null && dispatched !== null ? atMs(d.endedAt) - dispatched : null,
      }));
      record.deliveries = deliveries;
      if (step.class === "2xx" && deliveries.length === 0 && !isNotDelivered(key))
        findings.push({ kind: "not-delivered", case: key });
      if (step.class !== "2xx" && step.class !== undefined && deliveries.length > 0)
        findings.push({ kind: "delivered-without-accepted-create", case: key, class: step.class });
      if (step.class !== "2xx" && step.class !== "4xx" && step.class !== undefined)
        findings.push({ kind: "create-not-answered", case: key, class: step.class });
    }
    if (step.answer !== undefined)
      record.answer = JSON.parse(maskNumber(JSON.stringify(step.answer), projectNumber));
    cases[key] = record;
  }
  const delivered = Object.values(cases).reduce((n, c) => n + (c.deliveries?.length ?? 0), 0);
  return {
    cases,
    findings,
    totals: {
      cases: Object.keys(cases).length,
      sent: Object.values(cases).filter((c) => c.sent).length,
      deliveries: delivered,
      errorEntries: errors.length,
    },
    observationComplete: findings.length === 0,
  };
}
