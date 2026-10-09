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
function timestamp(value) {
  if (typeof value !== "string") return null;
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{3}|\d{6}|\d{9}))?Z$/.exec(value);
  if (!match) return null;
  const seconds = Date.parse(`${match[1]}Z`);
  if (!Number.isFinite(seconds) || new Date(seconds).toISOString().slice(0, 19) !== match[1])
    return null;
  return {
    instant: BigInt(seconds) * 1000000n + BigInt((match[2] ?? "").padEnd(9, "0")),
    precision: match[2]?.length ?? 0,
  };
}
export function sameVirtualInstant(requested, readback) {
  const a = timestamp(requested),
    b = timestamp(readback);
  return a !== null && b !== null && a.instant === b.instant;
}
function generatedEvidence() {
  const witnesses = [],
    publications = new Map(),
    snapshots = new Map(),
    pendingSnapshots = new Map(),
    sourceIds = new Map(),
    localIds = new Map();
  const ttl = 604800000000000n;
  function observe(dispatch, expected, actual) {
    if (!["Publish", "CreateSnapshot", "GetSnapshot"].includes(dispatch.method)) return;
    // A confirmed recorded absence has its own cursor witness; it does not revalidate a past pair.
    if (
      dispatch.method === "GetSnapshot" &&
      dispatch.category === "cursorGet" &&
      snapshots.has(dispatch.request.name) &&
      expected?.code === "NOT_FOUND" &&
      expected.unknown !== true &&
      actual?.code === "NOT_FOUND" &&
      actual.unknown !== true &&
      (dispatch.transport !== "rest" || (expected.status === 404 && actual.status === 404))
    )
      return;

    const witness = {
      cellId: dispatch.cellId,
      sourceRequestId: dispatch.requestId,
      sourceEvent: dispatch.n,
      method: dispatch.method,
      disposition: dispatch.method === "Publish" ? "Task22-106/107" : "owner1146",
      verdict: "NOT_COMPARABLE",
      reason: "generated correspondence incomplete",
      expiryEffects: "NOT_COMPARABLE_NOT_OBSERVED",
      physical:
        dispatch.transport === "grpc"
          ? "NOT_COMPARABLE_NATIVE_WIRE_NOT_CAPTURED"
          : "RAW_MEASURED_BYTES_PRESERVED",
      clockReadback: structuredClone(actual?.clockReadback ?? null),
    };
    witnesses.push(witness);
    const check = (ok, message, missing = false) => {
      if (!ok) {
        witness.verdict = missing ? "NOT_COMPARABLE" : "DIVERGES";
        witness.reason = message;
        throw witness;
      }
    };
    try {
      check(
        expected?.code === "OK" &&
          actual?.code === "OK" &&
          expected.unknown !== true &&
          actual.unknown !== true,
        "generated success response missing",
        actual?.unknown === true || uncertain.has(actual?.code),
      );
      if (dispatch.method === "Publish") {
        const source = expected.body?.messageIds,
          local = actual.body?.messageIds;
        check(
          Array.isArray(source) &&
            Array.isArray(local) &&
            source.length === dispatch.request.messages?.length &&
            local.length === source.length,
          "publication result cardinality differs",
        );
        check(
          same(Object.keys(expected.body).toSorted(), Object.keys(actual.body).toSorted()),
          "publication result field shape differs",
        );
        for (let i = 0; i < source.length; i++)
          check(
            typeof source[i] === "string" &&
              typeof local[i] === "string" &&
              /^[0-9]+$/.test(source[i]) &&
              /^[0-9]+$/.test(local[i]) &&
              source[i].length === local[i].length,
            "message ID width/alphabet differs",
          );
        check(
          new Set(source).size === source.length && new Set(local).size === local.length,
          "publication IDs are not unique",
        );
        source.forEach((id, i) =>
          check(!sourceIds.has(id) && !localIds.has(local[i]), "publication ID equality conflict"),
        );
        source.forEach((id, i) => {
          sourceIds.set(id, local[i]);
          localIds.set(local[i], id);
        });
        const clock = timestamp(actual.clockReadback?.clock),
          at = timestamp(dispatch.at);
        publications.set(dispatch.request.topic, {
          sourceRequestId: dispatch.requestId,
          clock:
            clock &&
            at &&
            clock.instant === at.instant &&
            actual.clockReadback.sourceRequestId === dispatch.requestId
              ? clock
              : null,
          sourceIds: [...source],
          localIds: [...local],
          request: structuredClone(dispatch.request),
        });
        witness.correspondence = source.map((id, i) => ({ source: id, local: local[i] }));
      } else {
        const source = expected.body,
          local = actual.body,
          sourceTime = timestamp(source?.expireTime),
          localTime = timestamp(local?.expireTime);
        check(
          sourceTime !== null && localTime !== null,
          "snapshot expiration presence/type/precision invalid",
        );
        check(
          sourceTime.precision === localTime.precision,
          "snapshot expiration precision differs",
        );
        const withoutTime = (body) => {
          const { expireTime: _generated, ...fields } = body;
          return fields;
        };
        check(
          same(withoutTime(source), withoutTime(local)) && local.name === dispatch.request.name,
          "snapshot identity/topic/labels/field shape differs",
        );
        if (dispatch.method === "CreateSnapshot") {
          const publication = publications.get(local.topic),
            clock = timestamp(actual.clockReadback?.clock),
            at = timestamp(dispatch.at);
          check(
            publication?.clock &&
              clock &&
              at &&
              clock.instant === at.instant &&
              actual.clockReadback.sourceRequestId === dispatch.requestId,
            "snapshot publication/clock binding missing",
            true,
          );
          check(
            localTime.instant === publication.clock.instant + ttl &&
              localTime.instant - clock.instant >= 3600000000000n &&
              localTime.instant - clock.instant <= ttl,
            "snapshot backlog lifetime differs",
          );
          check(
            !snapshots.has(local.name) && !pendingSnapshots.has(local.name),
            "snapshot creation identity repeated",
          );
          pendingSnapshots.set(local.name, {
            witness,
            sourceTime,
            localTime,
            body: structuredClone(local),
            publicationRef: publication.sourceRequestId,
            createRef: dispatch.requestId,
          });
          witness.publicationRef = publication.sourceRequestId;
          witness.createRef = dispatch.requestId;
          witness.sourceValue = source.expireTime;
          witness.localValue = local.expireTime;
          witness.reason = "snapshot stable Create/Get pair pending";
          return;
        } else {
          const saved = pendingSnapshots.get(local.name) ?? snapshots.get(local.name);
          check(saved !== undefined, "snapshot successful Create binding missing", true);
          check(
            same(saved.body, local) && sourceTime.instant === saved.sourceTime.instant,
            "snapshot Create/Get value drift",
          );
          snapshots.set(local.name, saved);
          pendingSnapshots.delete(local.name);
          saved.witness.verdict = "MATCH";
          saved.witness.reason = "successful stable Create/Get pair verified";
          witness.createRef = saved.createRef;
          witness.publicationRef = saved.publicationRef;
        }
        witness.sourceValue = source.expireTime;
        witness.localValue = local.expireTime;
      }
      witness.verdict = "MATCH";
      witness.reason = "bound generated value and unchanged shape verified";
    } catch (error) {
      if (error !== witness) throw error;
      if (dispatch.method === "GetSnapshot") {
        const saved =
          pendingSnapshots.get(dispatch.request.name) ?? snapshots.get(dispatch.request.name);
        if (saved) {
          saved.witness.verdict = witness.verdict;
          saved.witness.reason = witness.reason;
        }
        pendingSnapshots.delete(dispatch.request.name);
        snapshots.delete(dispatch.request.name);
      }
    }
  }
  return { witnesses, snapshots, observe };
}
// owner1146 witnesses are independent of the original recorded request judgments.
function ownListWitness({ cell, manifest, exchanges }, call, snapshots) {
  const witness = {
    cellId: cell.id,
    sourceSelectedMember: exchanges.find((e) => e.page?.stage === "first")?.page.names[0] ?? null,
    physical:
      cell.transport === "grpc"
        ? "NOT_COMPARABLE_NATIVE_WIRE_NOT_CAPTURED"
        : "RAW_MEASURED_BYTES_PRESERVED",
    disposition: "owner1146",
    verdict: "NOT_COMPARABLE",
    reason: "own cursor not observed",
    requests: [],
    expiryEffects: "NOT_COMPARABLE_NOT_OBSERVED",
  };
  const expected = new Map(
    (
      exchanges.find((e) => e.page?.stage === "baseline")?.response.reply.body?.[cell.kind] ?? []
    ).map((r) => [r.name, r]),
  );
  const live = new Set(),
    uncertainDeletes = new Set(),
    uncertainCreates = new Set(),
    unresolvedAbsences = new Set();
  let first = null,
    selected = null,
    sequence = 0,
    failed = false;
  const fail = (error) => {
    failed = true;
    witness.verdict = error.unknown ? "NOT_COMPARABLE" : "DIVERGES";
    witness.reason = error.message;
  };
  const check = (ok, message, unknown = false) => {
    if (!ok) {
      const error = new Error(message);
      error.unknown = unknown;
      throw error;
    }
  };
  const successful = (reply) =>
    object(reply) &&
    reply.unknown !== true &&
    !uncertain.has(reply.code) &&
    reply.code === "OK" &&
    (cell.transport !== "rest" || (reply.status >= 200 && reply.status < 300));
  const send = async (dispatch, request, method = dispatch.method) => {
    const ref = `${cell.id}:independent:${++sequence}`;
    const reply = await call({
      cellId: cell.id,
      transport: cell.transport,
      category: "semanticWitness",
      method,
      service: serviceOf(method),
      request,
      at: dispatch.at,
      requestId: ref,
      semanticRef: ref,
      sourceRequestId: dispatch.requestId,
    });
    witness.requests.push({
      ref,
      sourceEvent: dispatch.n,
      sourceRequestId: dispatch.requestId,
      originalRequest: structuredClone(dispatch.request),
      actualSemanticRequest: structuredClone(request),
      method,
      reply: structuredClone(reply),
    });
    check(
      reply?.unknown !== true && !uncertain.has(reply?.code),
      "unknown independent local effect",
      true,
    );
    return reply;
  };
  const page = (reply, size, allowed) => {
    check(
      successful(reply),
      "independent page refused",
      reply?.unknown === true || uncertain.has(reply?.code),
    );
    check(
      object(reply.body) &&
        Object.keys(reply.body).every((k) => [cell.kind, "nextPageToken"].includes(k)),
      "independent page field mismatch",
    );
    const members = reply.body[cell.kind] ?? [];
    check(Array.isArray(members) && members.length <= size, "independent page overflow");
    const names = members.map((r) => r?.name);
    check(new Set(names).size === names.length, "independent duplicate member");
    for (const r of members) {
      const source = expected.get(r?.name),
        saved = snapshots.get(r?.name);
      let equal = same(r, source);
      if (cell.kind === "snapshots") {
        check(saved !== undefined, "snapshot generated lifetime binding missing", true);
        const sourceTime = timestamp(source?.expireTime),
          localTime = timestamp(r?.expireTime);
        equal =
          sourceTime !== null &&
          localTime !== null &&
          sourceTime.precision === localTime.precision &&
          sourceTime.instant === saved.sourceTime.instant &&
          localTime.instant === saved.localTime.instant &&
          same({ ...r, expireTime: source.expireTime }, source);
      }
      check(
        object(r) && allowed.includes(r.name) && equal,
        "independent foreign member or resource field mismatch",
      );
    }
    const token = reply.body.nextPageToken ?? null;
    check(
      token === null || (typeof token === "string" && token.length > 0 && token.length <= 4096),
      "independent token shape mismatch",
    );
    return { members, names, token };
  };
  const walk = async (dispatch, initial, request, allowed) => {
    const names = [],
      members = [],
      tokens = new Set();
    let reply = initial,
      q = structuredClone(request);
    for (let n = 0; n <= manifest.manifest.members.length; n++) {
      const current = page(reply, q.pageSize, allowed);
      for (const r of current.members) {
        check(!names.includes(r.name), "independent duplicate full-walk member");
        names.push(r.name);
        members.push(r);
      }
      if (!current.token) {
        check(
          names.length === allowed.length && allowed.every((name) => names.includes(name)),
          "independent inventory missing member",
        );
        return { members, names, terminal: true };
      }
      check(!tokens.has(current.token), "independent repeated cursor");
      tokens.add(current.token);
      q = { ...request, pageToken: current.token };
      reply = await send(dispatch, q);
    }
    throw new Error("independent finite page bound exceeded");
  };
  return {
    witness,
    observe(dispatch, reply, actualRequest = dispatch.request) {
      witness.requests.push({
        ref: `${cell.id}:recorded:${dispatch.requestId}`,
        sourceEvent: dispatch.n,
        sourceRequestId: dispatch.requestId,
        originalRequest: structuredClone(dispatch.request),
        actualSemanticRequest: structuredClone(actualRequest),
        method: dispatch.method,
        reply: structuredClone(reply),
      });
      if (dispatch.method.startsWith("Create")) {
        if (successful(reply) && reply.body?.name === dispatch.request.name)
          live.add(dispatch.request.name);
        else if (reply?.unknown === true || uncertain.has(reply?.code))
          uncertainCreates.add(dispatch.request.name);
      }
      if (dispatch.method.startsWith("Delete")) {
        if (successful(reply)) live.delete(dispatch.request.name);
        else if (reply?.unknown === true || uncertain.has(reply?.code))
          uncertainDeletes.add(dispatch.request.name);
      }
    },
    async first(dispatch, reply) {
      if (failed) return;
      try {
        check(
          expected.size === manifest.manifest.members.length,
          "source full inventory unavailable",
          true,
        );
        check(
          manifest.manifest.members.every((name) => live.has(name)),
          "confirmed own resource creation missing",
          true,
        );
        const parsed = page(reply, dispatch.request.pageSize, manifest.manifest.members);
        check(parsed.names.length === 1 && parsed.token !== null, "own first cursor unavailable");
        first = {
          dispatch,
          request: structuredClone(dispatch.request),
          reply: structuredClone(reply),
          token: parsed.token,
        };
        selected = parsed.names[0];
        witness.selectedMember = selected;
        witness.sameSelectedMember = selected === witness.sourceSelectedMember;
        witness.before = await walk(dispatch, reply, dispatch.request, manifest.manifest.members);
      } catch (error) {
        fail(error);
      }
    },
    canReplace() {
      return first !== null && !failed;
    },
    unresolvedDelete(name) {
      return uncertainDeletes.has(name);
    },
    async action(dispatch, observed = null) {
      const request = { ...dispatch.request, name: selected };
      if (dispatch.category === "cursorDelete" && !observed) uncertainDeletes.add(selected);
      const reply = observed ?? (await send(dispatch, request));
      if (dispatch.category === "cursorDelete") {
        witness.deleted = reply;
        if (successful(reply)) {
          live.delete(selected);
          uncertainDeletes.delete(selected);
        } else uncertainDeletes.add(selected);
        check(
          successful(reply),
          "independent selected-member DELETE not confirmed",
          reply?.unknown === true || uncertain.has(reply?.code),
        );
      } else {
        witness.absence = reply;
        check(
          successful(witness.deleted),
          "independent selected-member DELETE not confirmed",
          witness.deleted?.unknown === true || uncertain.has(witness.deleted?.code),
        );
        check(
          reply?.unknown !== true && !uncertain.has(reply?.code),
          "independent selected-member absence unknown",
          true,
        );
        check(
          reply.code === "NOT_FOUND" && (cell.transport !== "rest" || reply.status === 404),
          "independent selected-member absence not confirmed",
        );
        const requestAfter = { ...first.request, pageToken: first.token };
        const replyAfter = await send({ ...dispatch, method: first.dispatch.method }, requestAfter);
        witness.after = await walk(
          { ...dispatch, method: first.dispatch.method },
          replyAfter,
          requestAfter,
          manifest.manifest.members.filter((n) => n !== selected),
        );
        witness.verdict = "MATCH";
        witness.reason =
          "own complete inventory, selected DELETE/absence and issued-cursor continuation verified";
      }
      return reply;
    },
    fail,
    async cleanup(dispatch) {
      for (const resource of manifest.manifest.resources.toReversed()) {
        if (!live.has(resource.name) || uncertainDeletes.has(resource.name)) continue;
        try {
          uncertainDeletes.add(resource.name);
          const deleted = await send(
            dispatch,
            { name: resource.name },
            resource.method.replace("Create", "Delete"),
          );
          if (!successful(deleted)) {
            uncertainDeletes.add(resource.name);
            check(false, "independent cleanup DELETE unresolved", true);
          }
          live.delete(resource.name);
          uncertainDeletes.delete(resource.name);
          unresolvedAbsences.add(resource.name);
          const absent = await send(
            dispatch,
            { name: resource.name },
            resource.method.replace("Create", "Get"),
          );
          check(
            absent.code === "NOT_FOUND" && (cell.transport !== "rest" || absent.status === 404),
            "independent cleanup absence unresolved",
            true,
          );
          unresolvedAbsences.delete(resource.name);
        } catch (error) {
          fail(error);
        }
      }
      witness.cleanup = {
        remaining: [...live],
        unknownCreates: [...uncertainCreates],
        unknownDeletes: [...uncertainDeletes],
        unresolvedAbsences: [...unresolvedAbsences],
        complete:
          live.size === 0 &&
          uncertainDeletes.size === 0 &&
          uncertainCreates.size === 0 &&
          unresolvedAbsences.size === 0,
      };
      if (!witness.cleanup.complete) {
        witness.verdict = "NOT_COMPARABLE";
        witness.reason = "independent owned cleanup unresolved";
      }
    },
  };
}
export async function replayRecording(input, call) {
  const rows = [],
    layoutDebts = [],
    semanticWitnesses = [];
  const generated = generatedEvidence();
  let localCount = 0;
  const countedCall = async (q) => {
    requireThat(
      ++localCount <= makePlan().caps.sourceRequests,
      "bounded local B semantic requests required",
    );
    return call(q);
  };
  for (const { cell, manifest, exchanges } of input.cells) {
    const tokens = new Map();
    const independent = ownListWitness(
      { cell, manifest, exchanges },
      countedCall,
      generated.snapshots,
    );
    semanticWitnesses.push(independent.witness);
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
      if (dispatch.method.startsWith("Delete") && independent.unresolvedDelete(request.name))
        reason = "unresolved own DELETE cannot retry";
      let judged;
      if (reason) {
        judged = result("NOT_COMPARABLE", reason, expected);
        if (["cursorDelete", "cursorGet"].includes(dispatch.category) && independent.canReplace()) {
          try {
            await independent.action(dispatch);
          } catch (error) {
            independent.fail(error);
          }
        }
      } else {
        // The transport receives only witnessed inputs, never an expected reply/status.
        const actual = await countedCall({
          cellId: cell.id,
          transport: cell.transport,
          category: dispatch.category,
          method: dispatch.method,
          service: serviceOf(dispatch.method),
          request,
          at: dispatch.at,
          requestId: dispatch.requestId,
        });
        independent.observe(dispatch, actual, request);
        generated.observe(dispatch, expected, actual);
        if (page?.stage === "first") await independent.first(dispatch, actual);
        if (["cursorDelete", "cursorGet"].includes(dispatch.category) && independent.canReplace()) {
          // Already-dispatched exact requests are retained; only the remaining own continuation is supplemental.
          if (dispatch.category === "cursorDelete") {
            try {
              await independent.action(dispatch, actual);
            } catch (error) {
              independent.fail(error);
            }
          } else {
            independent.witness.absence = actual;
            // The independent action must not resend a DELETE; the GET is an own read.
            try {
              await independent.action(dispatch, actual);
            } catch (error) {
              independent.fail(error);
            }
          }
        }
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
    await independent.cleanup(exchanges.at(-1).dispatch);
  }
  return {
    semanticWitnesses,
    generatedWitnesses: generated.witnesses,
    localSemanticRequests: localCount,
    suite: "pubsub-observation-b-replay-v1",
    sourceRunId: input.metadata.runId,
    rows,
    layoutDebts,
    parentClosureReady: false,
  };
}
