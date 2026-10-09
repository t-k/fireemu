// B-specific offline evidence import; production event identities are never rewritten into another suite.
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { makePlan, PROJECT } from "./plan.mjs";
import { graph } from "./scenarios.mjs";
import { encodeRequest, route } from "./wire.mjs";
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const same = (a, b) => isDeepStrictEqual(a, b);
const serviceOf = (method) => (/Topic|Publish/.test(method) ? "Publisher" : "Subscriber");
const uncertain = new Set([
  "UNKNOWN",
  "INTERNAL",
  "UNAVAILABLE",
  "DEADLINE_EXCEEDED",
  "CANCELLED",
  "DATA_LOSS",
  "RESOURCE_EXHAUSTED",
]);
const altered = (token) => (token[0] === "A" ? "B" : "A") + token.slice(1);
function requireThat(ok, message) {
  if (!ok) throw new Error(message);
}
export function importRecording(rows, summary) {
  requireThat(
    Array.isArray(rows) && rows.length > 0 && rows.length <= 5000 && object(summary),
    "bounded B events and summary required",
  );
  const starts = rows.filter((r) => r.event === "run-start"),
    plan = makePlan(),
    cells = plan.cells.filter((c) => !c.reserve);
  requireThat(starts.length === 1, "one genuine B run-start required");
  const metadata = starts[0];
  requireThat(
    metadata.suite === "pubsub-observation-b-v1" &&
      metadata.project === PROJECT &&
      /^[a-f0-9]{12}$/.test(metadata.runId ?? "") &&
      /^[a-f0-9]{40}$/.test(metadata.sourceHead ?? "") &&
      /^[a-f0-9]{64}$/.test(metadata.packetSha256 ?? ""),
    "B source identity required",
  );
  for (const key of ["suite", "project", "runId", "sourceHead", "envelopeId", "packetSha256"])
    requireThat(summary[key] === metadata[key], "B summary identity mismatch");
  requireThat(
    summary.a2 === false &&
      summary.recordingComplete === true &&
      summary.resourcesClosed === true &&
      summary.error === null &&
      summary.signalled === false &&
      summary.parentClosureReady === false,
    "complete closed source B summary required",
  );
  requireThat(
    Array.isArray(summary.results) &&
      same(
        summary.results.map((r) => r.cellId),
        cells.map((c) => c.id),
      ) &&
      summary.results.every((r) => r.complete === true && r.cleanupClosed === true),
    "exact18 complete B cells required",
  );
  let previous = -Infinity;
  rows.forEach((r, index) => {
    requireThat(
      object(r) &&
        r.n === index + 1 &&
        Number.isFinite(Date.parse(r.at)) &&
        Date.parse(r.at) >= previous,
      "B event chronology/sequence invalid",
    );
    previous = Date.parse(r.at);
  });
  const settlements = rows.filter((r) => r.event === "case-result");
  requireThat(
    same(
      settlements.map((r) => r.cellId),
      cells.map((c) => c.id),
    ) &&
      settlements.every(
        (r, i) =>
          r.complete === true &&
          r.cleanupClosed === true &&
          same(r.observations, summary.results[i].observations),
      ),
    "B recorded cell settlement mismatch",
  );
  const manifests = rows.filter((r) => r.event === "cell-manifest");
  requireThat(
    same(
      manifests.map((r) => r.cellId),
      cells.map((c) => c.id),
    ),
    "exact ordered B manifests required",
  );
  const dispatches = rows.filter((r) => r.event === "request-dispatch"),
    responses = rows.filter((r) => r.event === "response");
  requireThat(
    dispatches.length === responses.length &&
      dispatches.length === summary.meter?.requests &&
      dispatches.length <= plan.caps.sourceRequests,
    "B dispatch/response count mismatch",
  );
  requireThat(
    new Set(dispatches.map((r) => r.requestId)).size === dispatches.length &&
      new Set(responses.map((r) => r.requestId)).size === responses.length,
    "duplicate B exchange identity",
  );
  const imported = cells.map((cell) => {
    const manifest = manifests.find((r) => r.cellId === cell.id),
      declared = graph(cell, metadata.runId),
      owned = new Set(declared.resources.map((r) => r.name));
    requireThat(
      same(manifest.manifest, declared) &&
        same(
          manifest.creationOrder,
          declared.resources.map((r) => r.name),
        ) &&
        same(manifest.canonicalCoordinates, cell.coordinates),
      "declared B graph/creation order mismatch",
    );
    const calls = dispatches.filter((r) => r.cellId === cell.id);
    requireThat(
      same(
        calls
          .filter((r) => r.method.startsWith("Create"))
          .map((r) => ({ name: r.request.name, method: r.method, request: r.request })),
        declared.resources,
      ),
      "recorded B setup order mismatch",
    );
    const exchanges = calls.map((dispatch) => {
      requireThat(
        Number.isFinite(Date.parse(dispatch.requestDeadlineAt)) &&
          Date.parse(dispatch.requestDeadlineAt) >= Date.parse(dispatch.at),
        "B dispatch deadline invalid",
      );
      const response = responses.find((r) => r.requestId === dispatch.requestId);
      requireThat(
        response &&
          response.n > dispatch.n &&
          response.cellId === cell.id &&
          response.method === dispatch.method &&
          response.transport === dispatch.transport &&
          dispatch.transport === cell.transport &&
          object(response.reply),
        "B exchange provenance mismatch",
      );
      requireThat(
        dispatch.method.startsWith("List")
          ? dispatch.request.project === `projects/${PROJECT}`
          : owned.has(dispatch.request.name ?? dispatch.request.topic),
        "foreign B request identity",
      );
      for (const field of ["topic", "subscription"])
        if (dispatch.request[field] !== undefined)
          requireThat(owned.has(dispatch.request[field]), "foreign B prerequisite");
      const address =
        cell.transport === "rest"
          ? route(dispatch.method, dispatch.request, dispatch.routeName)
          : null;
      const bytes = address
        ? Buffer.from(address.body === undefined ? "" : JSON.stringify(address.body))
        : encodeRequest(serviceOf(dispatch.method), dispatch.method, dispatch.request);
      requireThat(
        digest(bytes) === dispatch.requestSha256 &&
          bytes.length === dispatch.requestBodyBytes &&
          (!address || (address.url === dispatch.url && address.verb === dispatch.verb)),
        "B request bytes/route provenance mismatch",
      );
      const nextDispatch = dispatches.find((r) => r.n > response.n);
      const page = rows.find(
        (r) =>
          r.event === "page-observation" &&
          r.cellId === cell.id &&
          r.n > response.n &&
          (!nextDispatch || r.n < nextDispatch.n),
      );
      if (dispatch.method.startsWith("List")) {
        requireThat(
          page &&
            same(page.reply, response.reply) &&
            page.requestToken === (dispatch.request.pageToken ?? null),
          "B page/response provenance mismatch",
        );
        requireThat(
          Array.isArray(page.names) &&
            new Set(page.names).size === page.names.length &&
            page.names.every((n) => declared.members.includes(n)) &&
            same(
              page.names,
              (response.reply.body?.[cell.kind] ?? []).map((r) => r.name),
            ) &&
            page.nextPageToken === (response.reply.body?.nextPageToken ?? null),
          "B page member/token evidence mismatch",
        );
        requireThat(
          same(
            page.projection,
            page.names.filter((n) => n.split("/").at(-1).startsWith(`fe${metadata.runId}-`)),
          ),
          "B ownership projection mismatch",
        );
      }
      return { dispatch, response, page };
    });
    const firstPage = exchanges.find((e) => e.page?.stage === "first")?.page;
    requireThat(
      firstPage?.names.length === 1 &&
        calls
          .filter((r) => r.category === "cursorDelete" || r.category === "cursorGet")
          .every((r) => r.request.name === firstPage.names[0]),
      "B cursor deletion identity mismatch",
    );
    requireThat(exchanges.length > 0, "empty B cell");
    return { cell, manifest, exchanges };
  });
  requireThat(
    dispatches.every((r) => cells.some((c) => c.id === r.cellId)),
    "undeclared B dispatched cell",
  );
  return { metadata, summary, cells: imported };
}
function result(semantic, reason, expected) {
  return {
    semantic,
    reason,
    ...(expected.layoutVerdict ? { layout: expected.layoutVerdict } : {}),
  };
}
export function compareReply(transport, expected, actual, { page = false } = {}) {
  if (
    !object(expected) ||
    !object(actual) ||
    expected.unknown === true ||
    actual.unknown === true ||
    uncertain.has(expected.code) ||
    uncertain.has(actual.code)
  )
    return result("NOT_COMPARABLE", "unknown response", expected ?? {});
  if (transport === "grpc") {
    if (typeof expected.code !== "string" || typeof actual.code !== "string")
      return result("NOT_COMPARABLE", "native status missing", expected);
    if (expected.code !== actual.code) return result("DIVERGES", "native code differs", expected);
    if (expected.code !== "OK") {
      const source = expected.body?.error?.message,
        local = actual.message ?? actual.body?.error?.message;
      if (typeof source !== "string" || typeof local !== "string")
        return result("NOT_COMPARABLE", "native details missing", expected);
      return {
        ...result(
          source === local ? "MATCH" : "DIVERGES",
          source === local ? "native code/details match" : "native details differ",
          expected,
        ),
        nativeEnvelope: "NOT_COMPARABLE_RICH_NATIVE_ERROR_DETAILS_NOT_CAPTURED",
      };
    }
  } else {
    if (
      ![expected.status, actual.status].every(
        (s) => Number.isInteger(s) && s >= 200 && s < 500 && !(s >= 300 && s < 400) && s !== 499,
      )
    )
      return result("NOT_COMPARABLE", "HTTP status missing/unknown", expected);
    if (expected.status !== actual.status)
      return result("DIVERGES", "HTTP status differs", expected);
  }
  if (!object(expected.body) || !object(actual.body))
    return result("NOT_COMPARABLE", "semantic body missing", expected);
  const body = (value) => {
    if (!page) return value;
    const { nextPageToken: _token, ...rest } = value;
    return rest;
  };
  if (!same(body(expected.body), body(actual.body)))
    return result("DIVERGES", "semantic body/member order differs", expected);
  if (page && Boolean(expected.body.nextPageToken) !== Boolean(actual.body.nextPageToken))
    return result("DIVERGES", "terminal page token state differs", expected);
  return result("MATCH", "recorded semantic body matches", expected);
}
export async function replayRecording(input, call) {
  const rows = [],
    layoutDebts = [];
  for (const { cell, manifest, exchanges } of input.cells) {
    const tokens = new Map();
    let firstSource = null,
      firstLocal = null,
      cursorReady = false;
    for (const { dispatch, response, page } of exchanges) {
      const expected = response.reply,
        request = structuredClone(dispatch.request);
      let reason = null;
      if (dispatch.category === "cursorDelete" || dispatch.category === "cursorGet") {
        if (!cursorReady) reason = "unbound cursor identity";
      }
      if (page?.stage === "altered-token") {
        if (!cursorReady || request.pageToken !== altered(firstSource))
          reason = "unbound altered cursor provenance";
        else request.pageToken = altered(firstLocal);
      } else if (request.pageToken !== undefined) {
        if (!tokens.has(request.pageToken)) reason = "unbound foreign/dependent cursor";
        else request.pageToken = tokens.get(request.pageToken);
      }
      if (page?.stage === "ownership-control" && firstSource !== null && !cursorReady)
        reason = "unbound cursor deletion dependency";
      let judged;
      if (reason) judged = result("NOT_COMPARABLE", reason, expected);
      else {
        // The transport receives only witnessed inputs, never an expected reply/status.
        const actual = await call({
          cellId: cell.id,
          transport: cell.transport,
          category: dispatch.category,
          method: dispatch.method,
          service: serviceOf(dispatch.method),
          request,
          at: dispatch.at,
          requestId: dispatch.requestId,
        });
        judged = compareReply(cell.transport, expected, actual, {
          page: Boolean(page) && expected.ok === true,
        });
        if (page && expected.ok === true && actual?.code === "OK" && actual.unknown !== true) {
          const members = actual.body?.[cell.kind],
            names = Array.isArray(members) ? members.map((r) => r?.name) : null;
          const identical =
            judged.semantic === "MATCH" &&
            same(names, page.names) &&
            new Set(names ?? []).size === (names?.length ?? -1) &&
            names?.every((n) => manifest.manifest.members.includes(n)) &&
            Boolean(page.nextPageToken) === Boolean(actual.body?.nextPageToken);
          if (
            identical &&
            page.nextPageToken &&
            typeof actual.body.nextPageToken === "string" &&
            actual.body.nextPageToken.length > 0 &&
            actual.body.nextPageToken.length <= 4096
          )
            tokens.set(page.nextPageToken, actual.body.nextPageToken);
          if (page.stage === "first") {
            firstSource = page.nextPageToken;
            firstLocal = actual.body?.nextPageToken;
            cursorReady =
              identical &&
              page.names.length === 1 &&
              tokens.has(firstSource) &&
              Boolean(firstLocal);
          }
        } else if (page?.stage === "first") {
          firstSource = page.nextPageToken;
          cursorReady = false;
        }
      }
      const item = {
        cellId: cell.id,
        requestId: dispatch.requestId,
        sourceEvent: dispatch.n,
        method: dispatch.method,
        transport: cell.transport,
        ...judged,
      };
      rows.push(item);
      if (expected.layoutVerdict?.startsWith("NOT_COMPARABLE"))
        layoutDebts.push({
          cellId: cell.id,
          requestId: dispatch.requestId,
          verdict: expected.layoutVerdict,
        });
    }
  }
  return {
    suite: "pubsub-observation-b-replay-v1",
    sourceRunId: input.metadata.runId,
    rows,
    layoutDebts,
    parentClosureReady: false,
  };
}
