import { isDeepStrictEqual } from "node:util";

const MARKER = "FE_EVENTS_FRAME ";

/** FE's stdout-origin filter, restricted to the two services identified by function readbacks. */
export function hLogRequest({ manifest: m, origins, start, end, pageToken }) {
  const originsText = origins
    .map(
      (o) =>
        `(logName="projects/${m.project}/logs/run.googleapis.com%2Fstdout" AND resource.type="cloud_run_revision" AND resource.labels.project_id="${m.project}" AND resource.labels.service_name="${o.service}" AND resource.labels.location="${o.location}")`,
    )
    .join(" OR ");
  return {
    method: "POST",
    path: "/v2/entries:list",
    op: "h.logs",
    label: { case: "h-capture" },
    body: {
      resourceNames: [`projects/${m.project}`],
      filter: `(${originsText}) AND timestamp>="${start}" AND timestamp<="${end}" AND (textPayload:"FE_EVENTS_FRAME" OR jsonPayload.message:"FE_EVENTS_FRAME")`,
      orderBy: "timestamp asc",
      pageSize: 200,
      ...(pageToken ? { pageToken } : {}),
    },
  };
}

/** Keep text and log/execution identities; only insertId deduplicates overlapping reads. */
export function parseHEntries(body, { manifest: m, origins, readAt, seen = new Set() }) {
  const result = { frames: [], incomplete: false, nextPageToken: null };
  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    (body.entries !== undefined && !Array.isArray(body.entries)) ||
    (body.nextPageToken !== undefined && typeof body.nextPageToken !== "string")
  )
    return { ...result, incomplete: true };
  result.nextPageToken = body.nextPageToken || null;
  for (const entry of body.entries ?? []) {
    const text = entry?.textPayload ?? entry?.jsonPayload?.message;
    let frame;
    try {
      frame = JSON.parse(text.slice(MARKER.length));
    } catch {
      result.incomplete = true;
      continue;
    }
    const origin = origins.find((o) => o.handler === frame?.handler);
    const labels = entry?.resource?.labels;
    const valid =
      typeof text === "string" &&
      text.startsWith(MARKER) &&
      origin &&
      entry.logName === `projects/${m.project}/logs/run.googleapis.com%2Fstdout` &&
      entry.resource?.type === "cloud_run_revision" &&
      labels?.project_id === m.project &&
      labels?.service_name === origin.service &&
      labels?.location === origin.location &&
      typeof entry.insertId === "string" &&
      entry.insertId.length > 0 &&
      Number.isFinite(Date.parse(entry.timestamp)) &&
      frame.generation === 2 &&
      frame.run === m.runId &&
      frame.recording === m.recording &&
      typeof frame.case === "string" &&
      typeof frame.invocationId === "string" &&
      ["failed", "succeeded"].includes(frame.attempt) &&
      frame.event &&
      !Array.isArray(frame.event) &&
      typeof frame.event.id === "string" &&
      typeof frame.event.source === "string" &&
      frame.correlation?.id === frame.event.id &&
      frame.correlation?.source === frame.event.source &&
      isDeepStrictEqual(frame.eventKeys, Object.keys(frame.event));
    if (!valid) {
      result.incomplete = true;
      continue;
    }
    if (seen.has(entry.insertId)) continue;
    seen.add(entry.insertId);
    result.frames.push({
      insertId: entry.insertId,
      logTimestamp: entry.timestamp,
      executionId: entry.labels?.execution_id ?? null,
      readAt,
      text,
      frame,
    });
  }
  return result;
}

/** Bounded evidence only: even a frame ingested after the window defeats non-delivery. */
export function judgeH({ manifest: m, observations, capture }) {
  const results = observations.map((o) => {
    const candidates = o.candidates ?? [];
    const matching = capture.frames.filter(({ frame }) =>
      candidates.some((e) => e.id === frame.event.id && e.source === frame.event.source),
    );
    const invalidCorrelation = matching.some(
      ({ frame }) =>
        !candidates.some(
          (e) =>
            e.id === frame.event.id &&
            e.source === frame.event.source &&
            (e.type === undefined ||
              (e.type === frame.event.type &&
                ((frame.handler === m.observe && e.type === m.type) ||
                  (frame.handler === m.filtered && e.type === m.filteredType)))),
        ),
    );
    const received = (handler) => matching.filter((f) => f.frame.handler === handler);
    const positive = (o.positiveHandlers ?? []).every((h) =>
      candidates
        .filter((e) => e.type !== undefined)
        .every((e) =>
          received(h).some((f) => f.frame.event.id === e.id && f.frame.event.source === e.source),
        ),
    );
    const expected =
      o.expectedRecipients ??
      (o.negativeHandlers?.length || o.refused
        ? []
        : candidates.map((e) => ({ ...e, handler: m.observe })));
    const receipts = expected.every((e) =>
      received(e.handler).some(
        (f) => f.frame.event.id === e.id && f.frame.event.source === e.source,
      ),
    );
    const negativeFrames = matching.filter((f) => o.negativeHandlers?.includes(f.frame.handler));
    let retry = true;
    if (o.retryHandler) {
      const attempts = received(o.retryHandler);
      const within = (f) =>
        Date.parse(f.logTimestamp) >= o.sentAt &&
        Date.parse(f.logTimestamp) <= o.sentAt + 600_000 &&
        Date.parse(f.readAt) <= o.sentAt + 600_000;
      retry = attempts.some(
        (failed, i) =>
          within(failed) &&
          failed.frame.attempt === "failed" &&
          attempts
            .slice(i + 1)
            .some(
              (success) =>
                within(success) &&
                Date.parse(success.logTimestamp) >= Date.parse(failed.logTimestamp) &&
                success.frame.attempt === "succeeded" &&
                success.frame.invocationId !== failed.frame.invocationId &&
                isDeepStrictEqual(success.frame.event, failed.frame.event),
            ),
      );
    }
    const windowMs = o.windowMs ?? (o.negativeHandlers?.length || o.refused ? 120_000 : 0);
    const accepted = o.refused
      ? o.status >= 400 && o.status < 500
      : o.status >= 200 && o.status < 300;
    const complete =
      capture.complete &&
      capture.finalRead &&
      o.known &&
      accepted &&
      !invalidCorrelation &&
      positive &&
      receipts &&
      retry &&
      (!windowMs || (o.before && o.after && o.endedAt - o.sentAt >= windowMs));
    const delivered = matching.map((f) => ({
      handler: f.frame.handler,
      id: f.frame.event.id,
      source: f.frame.event.source,
      insertId: f.insertId,
      attempt: f.frame.attempt,
    }));
    return {
      case: o.case,
      complete,
      outcome: !complete
        ? "incomplete"
        : negativeFrames.length
          ? "delivered"
          : o.negativeHandlers?.length
            ? "bounded-non-delivery"
            : o.refused
              ? "refused-batch-subset"
              : "observed",
      delivered,
    };
  });
  return {
    complete: capture.complete && capture.finalRead && results.every((o) => o.complete),
    observations: results,
  };
}

/** FE's overlapping polls plus final whole-window reread, within the fixed H capture meter. */
export function hCapture({ manifest, origins, transport, now, startedAt, saveFrame }) {
  const frames = [];
  const seen = new Set();
  let lastEnd = startedAt;
  let complete = true;
  let finalRead = false;
  let requests = 0;
  async function read(start, maxPages) {
    const end = now();
    let pageToken;
    for (let page = 0; page < maxPages; page++) {
      if (requests >= 120) {
        complete = false;
        return;
      }
      requests++;
      const reply = await transport.request(
        hLogRequest({
          manifest,
          origins,
          start: new Date(start).toISOString(),
          end: new Date(end).toISOString(),
          pageToken,
        }),
      );
      if (reply.unknown || reply.status !== 200) {
        complete = false;
        return;
      }
      const parsed = parseHEntries(reply.body, {
        manifest,
        origins,
        readAt: new Date(now()).toISOString(),
        seen,
      });
      if (parsed.incomplete) complete = false;
      for (const frame of parsed.frames) {
        frames.push(frame);
        saveFrame(frame);
      }
      pageToken = parsed.nextPageToken;
      if (!pageToken) {
        lastEnd = end;
        return true;
      }
    }
    complete = false;
  }
  return {
    poll: () => read(Math.max(startedAt, lastEnd - 30_000), 5),
    finish: async () => {
      finalRead = (await read(startedAt, 20)) === true;
    },
    result: () => ({ frames, complete, finalRead, requests }),
  };
}
