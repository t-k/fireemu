// Actual local facets under the limited omitted-order/intermediate-timing disposition.
// This module neither changes replay verdicts nor grants case or parent closure.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";
import { isDeepStrictEqual } from "node:util";
const nativeInputs = new WeakSet();
const collectors = new WeakMap();
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const clone = (value) => structuredClone(value);
function freeze(value) {
  if (value && typeof value === "object") {
    for (const x of Object.values(value)) freeze(x);
    Object.freeze(value);
  }
  return value;
}
const collectionPattern = /^\/v1\/(projects\/[^/?#]+\/locations\/[^/?#]+\/channels)$/;
const channelPattern = /^projects\/[^/?#]+\/locations\/[^/?#]+\/channels\/[^/?#]+$/;
const timestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$/;
function checkTimestamp(value) {
  assert.match(value, timestamp);
  assert.ok(Number.isFinite(Date.parse(value)), "timestamp date");
  assert.equal(
    new Date(value).toISOString().slice(0, 19),
    value.slice(0, 19),
    "timestamp calendar",
  );
}
function resourceIdentity(value) {
  assert.ok(value && channelPattern.test(value.name), "channel identity");
  assert.match(value.uid, /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  for (const key of ["createTime", "updateTime"]) checkTimestamp(value[key]);
}
function resource(
  value,
  expectedState = "ACTIVE",
  topicProject = value.name.split("/")[1],
  terminal = false,
) {
  resourceIdentity(value);
  resourceFields(value, terminal);
  assert.equal(value.state, expectedState);
  assert.equal(typeof value.pubsubTopic, "string");
  assert.ok(value.pubsubTopic.startsWith(`projects/${topicProject}/topics/`));
  assert.match(value.pubsubTopic, /-\d{3}$/);
}
function resourceFields(value, terminal = false) {
  assert.deepEqual(
    Object.keys(value),
    [
      ...(terminal ? ["@type"] : []),
      "name",
      "uid",
      "createTime",
      "updateTime",
      "pubsubTopic",
      "state",
    ],
    "active resource fields",
  );
}
function terminalResource(body, target, verb, topicProject = target.split("/")[1]) {
  assert.equal(body?.["@type"], "type.googleapis.com/google.cloud.eventarc.v1.Channel");
  assert.equal(body.name, target);
  if (verb === "create") {
    resource(body, "ACTIVE", topicProject, true);
  } else {
    assert.equal(verb, "delete");
    assert.deepEqual(Object.keys(body), ["@type", "name", "state", "pubsubTopic"]);
    assert.equal(body.state, "INACTIVE");
    assert.equal(body.pubsubTopic, "");
  }
}
function ownPoll(row, issued, target, verb) {
  assert.equal(row.response.status, 200);
  assert.equal(row.request.method, "GET");
  assert.equal(row.request.path, `/v1/${issued.body.name}`, "own poll path");
  assert.equal(row.body.name, issued.body.name);
  assert.equal(
    row.body.metadata?.createTime,
    issued.body.metadata.createTime,
    "operation createTime changed",
  );
  operation(row.body, target, verb);
}
/** Bind exact requests to a checked native journal, never install recorded answers locally. */
export function loadNativeRequests({ path, sha256, ordinals }) {
  const bytes = readFileSync(path);
  assert.equal(sha(bytes), sha256, "native input digest");
  assert.ok(Array.isArray(ordinals) && new Set(ordinals).size === ordinals.length);
  const wanted = new Set(ordinals),
    result = new Map();
  for (const line of bytes.toString("utf8").split("\n").filter(Boolean)) {
    const row = JSON.parse(line);
    if (!wanted.has(row.n)) continue;
    assert.ok(!result.has(row.n), "duplicate native ordinal");
    assert.ok(row.request && typeof row.request.path === "string");
    const value = freeze({
      request: clone(row.request),
      recorded: clone(row.response),
      source: { path, sha256, n: row.n, requestSha256: sha(JSON.stringify(row.request)) },
    });
    nativeInputs.add(value);
    result.set(row.n, value);
  }
  assert.equal(result.size, wanted.size, "missing native input");
  return result;
}
function bound(input) {
  assert.ok(nativeInputs.has(input), "unbound native input");
}
function state(collector) {
  const value = collectors.get(collector);
  assert.ok(value, "unknown collector");
  return value;
}
/** Listener ownership remains with the existing exec session; no child or server is launched. */
export function createCollector({
  base,
  fetchImpl = fetch,
  timeoutMs = 30000,
  maxElapsedMs = 120000,
  maxRequests = 200,
}) {
  const url = new URL(base);
  assert.equal(url.protocol, "http:");
  assert.ok(["127.0.0.1", "[::1]"].includes(url.hostname), "numeric loopback required");
  assert.equal(url.pathname, "/");
  assert.ok(!url.search && !url.hash && !url.username && !url.password);
  for (const n of [timeoutMs, maxElapsedMs, maxRequests])
    assert.ok(Number.isSafeInteger(n) && n > 0);
  const exchanges = [];
  const collector = {
    get exchanges() {
      return Object.freeze([...exchanges]);
    },
  };
  collectors.set(collector, {
    base: url.origin,
    fetchImpl,
    timeoutMs,
    maxElapsedMs,
    maxRequests,
    start: performance.now(),
    issued: new WeakSet(),
    unfinished: new WeakMap(),
    exchanges,
  });
  return collector;
}
async function call(collector, request, source, derivedFrom, timeoutOverride) {
  const s = state(collector);
  assert.ok(collector.exchanges.length < s.maxRequests, "request bound");
  assert.ok(
    request.path.startsWith("/v1/") && !request.path.includes("#") && !request.path.includes("\\"),
    "local API path",
  );
  const url = new URL(s.base + request.path);
  assert.equal(url.origin, s.base);
  const remaining = s.maxElapsedMs - (performance.now() - s.start);
  assert.ok(remaining > 0, "elapsed bound");
  const timeout = Math.max(1, Math.min(s.timeoutMs, remaining, timeoutOverride ?? Infinity));
  const controller = new AbortController();
  const raw =
    request.body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(request.body));
  const exchange = {
    id: collector.exchanges.length,
    source: clone(source),
    derivedFrom: derivedFrom ?? null,
    request: clone(request),
    sentMonotonicMs: performance.now(),
    requestBytes: raw.length,
    requestBase64: raw.toString("base64"),
    requestSha256: sha(raw),
  };
  s.exchanges.push(exchange);
  let timer;
  try {
    const result = await Promise.race([
      (async () => {
        const reply = await s.fetchImpl(url.href, {
          method: request.method ?? "GET",
          headers: {
            authorization: "Bearer ya29.replay-token",
            ...(raw.length ? { "content-type": "application/json" } : {}),
          },
          body: request.body === undefined ? undefined : raw,
          redirect: "error",
          signal: controller.signal,
        });
        assert.equal(reply.redirected, false, "redirected response");
        const bytes = Buffer.from(await reply.arrayBuffer());
        return {
          status: reply.status,
          headers: Object.fromEntries(reply.headers),
          text: bytes.toString("utf8"),
          bytes: bytes.length,
          base64: bytes.toString("base64"),
          sha256: sha(bytes),
        };
      })(),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new Error("transport timeout"));
        }, timeout);
      }),
    ]);
    exchange.receivedMonotonicMs = performance.now();
    exchange.response = result;
    assert.equal(result.headers["content-type"], "application/json; charset=UTF-8", "content type");
    assert.equal(result.headers["content-length"], String(result.bytes), "content length");
    exchange.body = JSON.parse(result.text);
    return exchange;
  } catch (error) {
    exchange.failure = { name: error.name, message: error.message };
    throw error;
  } finally {
    clearTimeout(timer);
    freeze(exchange);
  }
}
function inventoryRows(reply, collection) {
  assert.equal(reply.response.status, 200);
  assert.ok(Array.isArray(reply.body.channels));
  assert.deepEqual(Object.keys(reply.body), ["channels"], "inventory fields");
  assert.equal(Object.hasOwn(reply.body, "nextPageToken"), false, "inventory incomplete");
  const result = new Map(),
    uids = new Set();
  for (const ch of reply.body.channels) {
    resource(ch);
    assert.ok(ch.name.startsWith(collection + "/"));
    assert.ok(!result.has(ch.name) && !uids.has(ch.uid), "duplicate inventory");
    result.set(ch.name, ch);
    uids.add(ch.uid);
  }
  return result;
}
/** Walk only a native first page, with each continuation from its own actual issuing reply. */
export async function collectOwnCursorWalk({ collector, root, inventory }) {
  bound(root);
  bound(inventory);
  const [bare, query = ""] = root.request.path.split(/\?(.*)/s, 2),
    match = collectionPattern.exec(bare);
  assert.ok(match, "list collection");
  assert.equal(root.request.method, "GET");
  assert.equal(inventory.request.method, "GET");
  assert.equal(inventory.request.path, bare, "inventory scope");
  assert.equal(root.recorded?.status, 200);
  assert.ok(Array.isArray(root.recorded.body?.channels));
  const params = new URLSearchParams(query);
  assert.equal(params.getAll("pageToken").length, 0, "unissued root cursor");
  assert.equal(params.getAll("orderBy").length, 0, "order outside disposition");
  assert.equal(params.getAll("filter").length, 0, "filter outside supplied witnesses");
  assert.equal(params.getAll("pageSize").length, 1);
  const size = Number(params.get("pageSize"));
  assert.ok(Number.isSafeInteger(size) && size > 0);
  const before = await call(collector, inventory.request, inventory.source);
  const expected = inventoryRows(before, match[1]);
  assert.equal(inventory.recorded?.status, 200);
  assert.ok(Array.isArray(inventory.recorded.body?.channels));
  const nativeNames = inventory.recorded.body.channels.map((x) => x.name);
  for (const channel of inventory.recorded.body.channels) {
    assert.deepEqual(
      Object.keys(expected.get(channel.name) ?? {}),
      Object.keys(channel),
      "unrecorded resource fields",
    );
  }
  assert.equal(new Set(nativeNames).size, nativeNames.length);
  assert.deepEqual(new Set(expected.keys()), new Set(nativeNames), "native inventory names");
  const seen = new Set(),
    tokens = new Set(),
    uids = new Set(),
    pages = [];
  let path = root.request.path,
    issuer = null;
  for (let page = 0; page <= expected.size; page++) {
    const row = await call(collector, { ...root.request, path }, root.source, issuer);
    assert.equal(row.response.status, 200);
    assert.ok(Array.isArray(row.body.channels));
    assert.deepEqual(
      Object.keys(row.body),
      Object.hasOwn(row.body, "nextPageToken") ? ["channels", "nextPageToken"] : ["channels"],
      "page fields",
    );
    assert.ok(row.body.channels.length > 0 && row.body.channels.length <= size, "page size bound");
    for (const channel of row.body.channels) {
      resource(channel);
      assert.ok(expected.has(channel.name), "foreign member");
      assert.ok(!seen.has(channel.name) && !uids.has(channel.uid), "duplicate member");
      assert.ok(isDeepStrictEqual(channel, expected.get(channel.name)), "full resource changed");
      seen.add(channel.name);
      uids.add(channel.uid);
    }
    pages.push(row.id);
    const token = row.body.nextPageToken;
    if (!Object.hasOwn(row.body, "nextPageToken")) {
      assert.equal(seen.size, expected.size, "missing tail");
      break;
    }
    assert.ok(
      typeof token === "string" &&
        /^[A-Za-z0-9_-]+$/.test(token) &&
        Buffer.from(token, "base64url").toString("base64url") === token,
      "invalid cursor",
    );
    assert.ok(!tokens.has(token), "repeated cursor");
    assert.ok(seen.size < expected.size, "missing terminal tail");
    tokens.add(token);
    issuer = row.id;
    path = root.request.path + `${query ? "&" : "?"}pageToken=${encodeURIComponent(token)}`;
  }
  const after = await call(collector, inventory.request, inventory.source);
  const final = inventoryRows(after, match[1]);
  assert.ok(isDeepStrictEqual(final, expected), "inventory changed");
  return freeze({
    kind: "own-cursor-walk",
    complete: true,
    source: root.source,
    inventorySource: inventory.source,
    resourceCount: seen.size,
    pages,
    before: before.id,
    after: after.id,
  });
}
function operation(body, target, verb) {
  const parent = target.slice(0, target.lastIndexOf("/channels/"));
  assert.ok(typeof body?.name === "string" && body.name.startsWith(parent + "/operations/"));
  assert.match(
    body.name.slice((parent + "/operations/").length),
    /^operation-\d{13}-[a-f0-9]{13}-[a-f0-9]{8}-[a-f0-9]{8}$/,
  );
  assert.equal(body.metadata?.target, target);
  assert.equal(body.metadata?.verb, verb);
  assert.equal(typeof body.done, "boolean");
  assert.equal(
    body.metadata["@type"],
    "type.googleapis.com/google.cloud.eventarc.v1.OperationMetadata",
  );
  checkTimestamp(body.metadata.createTime);
  assert.equal(body.metadata.requestedCancellation, false);
  assert.equal(body.metadata.apiVersion, "v1");
  assert.deepEqual(
    Object.keys(body),
    body.done ? ["name", "metadata", "done", "response"] : ["name", "metadata", "done"],
    "operation fields",
  );
  assert.deepEqual(
    Object.keys(body.metadata),
    [
      "@type",
      "createTime",
      ...(body.done ? ["endTime"] : []),
      "target",
      "verb",
      "requestedCancellation",
      "apiVersion",
    ],
    "metadata fields",
  );
  if (body.done) {
    checkTimestamp(body.metadata.endTime);
    assert.ok(body.metadata.endTime >= body.metadata.createTime, "operation time order");
  } else assert.equal(Object.hasOwn(body.metadata, "endTime"), false);
  if (!body.done) assert.equal(Object.hasOwn(body, "response"), false, "unfinished response");
  assert.equal(Object.hasOwn(body, "error"), false, "operation error");
}
/** Accept only an own successful native create/delete issuing exchange. */
export async function issueOperation({ collector, input }) {
  bound(input);
  assert.equal(input.recorded?.status, 200, "native issuing failure");
  const request = input.request;
  let target, verb;
  if (request.method === "POST") {
    const [bare, q = ""] = request.path.split(/\?(.*)/s, 2),
      match = collectionPattern.exec(bare),
      params = new URLSearchParams(q);
    assert.ok(match);
    assert.equal(params.getAll("channelId").length, 1);
    const id = params.get("channelId");
    assert.ok(id && !/[/?#]/.test(id));
    target = match[1] + "/" + id;
    assert.equal(request.body?.name, target);
    verb = "create";
  } else {
    assert.equal(request.method, "DELETE");
    target = request.path.slice(4);
    assert.ok(request.path.startsWith("/v1/") && channelPattern.test(target));
    verb = "delete";
  }
  operation(input.recorded.body, target, verb);
  const row = await call(collector, request, input.source);
  assert.equal(row.response.status, 200);
  operation(row.body, target, verb);
  const issued = freeze({
    name: row.body.name,
    target,
    verb,
    exchange: row.id,
    source: input.source,
  });
  state(collector).issued.add(issued);
  return issued;
}
/** Poll the unchanged own identity on ordinary elapsed time; never inject a recorded duration. */
async function pollOperationTerminal({
  collector,
  issued,
  timeoutMs = 30000,
  pollIntervalMs = 100,
}) {
  const s = state(collector);
  assert.ok(s.issued.has(issued), "unissued operation");
  for (const n of [timeoutMs, pollIntervalMs]) assert.ok(Number.isSafeInteger(n) && n > 0);
  const deadline = performance.now() + timeoutMs;
  let row;
  while (performance.now() < deadline) {
    row = await call(
      collector,
      { method: "GET", path: `/v1/${issued.name}` },
      issued.source,
      issued.exchange,
      deadline - performance.now(),
    );
    ownPoll(row, collector.exchanges[issued.exchange], issued.target, issued.verb);
    if (row.body.done) break;
    await delay(Math.min(pollIntervalMs, Math.max(0, deadline - performance.now())));
  }
  assert.ok(row?.body.done, "terminal timeout");
  terminalResource(row.body.response, issued.target, issued.verb);
  return { row, deadline };
}
export async function collectOperationTerminal(options) {
  const { collector, issued } = options;
  const { row, deadline } = await pollOperationTerminal(options);
  const terminal = row.id;
  assert.ok(performance.now() < deadline, "terminal timeout");
  const later = await call(
    collector,
    { method: "GET", path: `/v1/${issued.target}` },
    issued.source,
    terminal,
    deadline - performance.now(),
  );
  if (issued.verb === "delete") {
    assert.equal(later.response.status, 404);
    assert.equal(later.body.error?.code, 404);
    assert.equal(later.body.error?.status, "NOT_FOUND");
    assert.equal(typeof later.body.error?.message, "string");
  } else {
    assert.equal(later.response.status, 200);
    resource(later.body);
    for (const key of ["name", "uid", "createTime", "pubsubTopic", "state"])
      assert.equal(later.body[key], row.body.response[key], "terminal resource identity");
  }
  return freeze({
    kind: "own-operation-terminal",
    complete: true,
    source: issued.source,
    issuedExchange: issued.exchange,
    terminalExchange: terminal,
    readbackExchange: later.id,
    name: issued.name,
    target: issued.target,
    verb: issued.verb,
  });
}

/** Record the native creating shape and own unfinished identity before a paired DELETE. */
function unfinishedResource(body) {
  assert.deepEqual(Object.keys(body), ["name", "uid", "createTime", "updateTime", "pubsubTopic"]);
  assert.equal(body.pubsubTopic, "");
  assert.equal(Object.hasOwn(body, "state"), false);
  resourceIdentity(body);
}
export async function observeUnfinishedCreate({ collector, issued }) {
  const s = state(collector);
  assert.ok(s.issued.has(issued));
  assert.equal(issued.verb, "create");
  const channel = await call(
    collector,
    { method: "GET", path: `/v1/${issued.target}` },
    issued.source,
    issued.exchange,
  );
  assert.equal(channel.response.status, 200);
  assert.equal(channel.body.name, issued.target);
  unfinishedResource(channel.body);
  const unfinished = await call(
    collector,
    { method: "GET", path: `/v1/${issued.name}` },
    issued.source,
    issued.exchange,
  );
  assert.equal(unfinished.response.status, 200);
  assert.equal(unfinished.body.name, issued.name);
  operation(unfinished.body, issued.target, "create");
  assert.equal(unfinished.body.done, false);
  assert.equal(
    unfinished.body.metadata.createTime,
    collector.exchanges[issued.exchange].body.metadata.createTime,
  );
  const marker = freeze({ channelExchange: channel.id, operationExchange: unfinished.id });
  s.unfinished.set(issued, marker);
  return marker;
}
/** Only an explicitly observed unfinished CREATE may skip its ordinary ACTIVE GET in this pair. */
export async function collectPairedOperationTerminals({
  collector,
  create,
  deleted,
  timeoutMs = 30000,
  pollIntervalMs = 100,
}) {
  const s = state(collector),
    start = s.unfinished.get(create);
  assert.ok(start, "missing unfinished-start proof");
  assert.ok(s.issued.has(create) && s.issued.has(deleted));
  assert.equal(create.verb, "create");
  assert.equal(deleted.verb, "delete");
  assert.equal(create.target, deleted.target);
  assert.notEqual(create.name, deleted.name, "distinct own operations");
  assert.ok(
    create.exchange < start.operationExchange && start.operationExchange < deleted.exchange,
    "delete must follow unfinished observation",
  );
  const deadline = performance.now() + timeoutMs;
  const active = await pollOperationTerminal({
    collector,
    issued: create,
    timeoutMs,
    pollIntervalMs,
  });
  for (const key of ["name", "uid", "createTime"])
    assert.equal(
      active.row.body.response[key],
      collector.exchanges[start.channelExchange].body[key],
      "paired resource identity changed",
    );
  const remaining = Math.floor(deadline - performance.now());
  assert.ok(remaining > 0, "paired terminal timeout");
  const inactive = await collectOperationTerminal({
    collector,
    issued: deleted,
    timeoutMs: remaining,
    pollIntervalMs,
  });
  return freeze({
    kind: "paired-own-operation-terminals",
    complete: true,
    createSource: create.source,
    deleteSource: deleted.source,
    start,
    createIssuedExchange: create.exchange,
    createTerminalExchange: active.row.id,
    deleteIssuedExchange: deleted.exchange,
    deleteTerminal: inactive,
    target: create.target,
  });
}

/** Recheck retained collector exchanges with the same resource and operation predicates. */
export function validateRetainedProofs(report, nativeInventories) {
  assert.equal(report.complete, true, "incomplete lifecycle report");
  assert.ok(Array.isArray(report.proofs) && report.proofs.length, "missing lifecycle proofs");
  const exchanges = report.exchanges;
  assert.ok(Array.isArray(exchanges) && exchanges.length, "missing lifecycle exchanges");
  for (const [index, exchange] of exchanges.entries()) {
    assert.equal(exchange.id, index, "exchange identity");
    assert.ok(!exchange.failure, "failed lifecycle exchange");
    const bytes = Buffer.from(exchange.response.base64, "base64");
    assert.equal(bytes.toString("base64"), exchange.response.base64);
    assert.equal(bytes.length, exchange.response.bytes);
    assert.equal(sha(bytes), exchange.response.sha256);
    assert.equal(exchange.response.headers["content-length"], String(bytes.length));
    assert.deepEqual(JSON.parse(bytes.toString()), exchange.body, "physical lifecycle body");
    const requestBytes = Buffer.from(exchange.requestBase64, "base64");
    assert.equal(requestBytes.toString("base64"), exchange.requestBase64);
    assert.equal(requestBytes.length, exchange.requestBytes);
    assert.equal(sha(requestBytes), exchange.requestSha256);
    assert.ok(
      Number.isFinite(exchange.sentMonotonicMs) &&
        exchange.receivedMonotonicMs >= exchange.sentMonotonicMs,
    );
    if (index > 0)
      assert.ok(
        exchange.sentMonotonicMs >= exchanges[index - 1].receivedMonotonicMs,
        "retained exchange chronology",
      );
  }
  const accounted = new Set();
  const at = (id) => {
    assert.ok(
      Number.isSafeInteger(id) && id >= 0 && id < exchanges.length,
      "missing proof exchange",
    );
    accounted.add(id);
    return exchanges[id];
  };
  const terminal = (proof, createOnly = false) => {
    const issued = at(proof.issuedExchange),
      ended = at(proof.terminalExchange);
    assert.ok(issued.id < ended.id, "terminal order");
    assert.deepEqual(issued.source, proof.source, "issuing native binding");
    assert.equal(issued.response.status, 200);
    operation(issued.body, proof.target, proof.verb);
    if (proof.verb === "create") {
      assert.equal(issued.request.method, "POST");
      assert.equal(issued.request.body?.name, proof.target);
      const url = new URL(issued.request.path, "http://127.0.0.1");
      assert.equal(url.pathname, `/v1/${proof.target.slice(0, proof.target.lastIndexOf("/"))}`);
      assert.equal(url.searchParams.get("channelId"), proof.target.split("/").at(-1));
    } else {
      assert.equal(issued.request.method, "DELETE");
      assert.equal(issued.request.path, `/v1/${proof.target}`);
    }
    assert.equal(issued.body.name, proof.name);
    let previous = issued;
    for (const poll of exchanges
      .slice(issued.id + 1, ended.id + 1)
      .filter(
        (row) =>
          row.request.path === `/v1/${proof.name}` ||
          (row.derivedFrom === issued.id && row.request.path !== `/v1/${proof.target}`),
      )) {
      ownPoll(poll, issued, proof.target, proof.verb);
      accounted.add(poll.id);
      assert.equal(poll.derivedFrom, issued.id, "own poll linkage");
      assert.deepEqual(poll.source, proof.source, "own poll native binding");
      assert.ok(poll.sentMonotonicMs >= previous.receivedMonotonicMs, "own poll chronology");
      if (previous.body.done) assert.equal(poll.body.done, true, "operation regressed");
      if (poll.body.done) terminalResource(poll.body.response, proof.target, proof.verb);
      previous = poll;
    }
    assert.equal(previous.id, ended.id, "missing terminal poll");
    assert.equal(ended.response.status, 200);
    assert.equal(ended.request.path, `/v1/${proof.name}`);
    assert.equal(ended.derivedFrom, issued.id, "own terminal identity binding");
    operation(ended.body, proof.target, proof.verb);
    assert.equal(ended.body.name, proof.name);
    assert.equal(ended.body.metadata.createTime, issued.body.metadata.createTime);
    assert.equal(ended.body.done, true, "nonterminal proof");
    terminalResource(ended.body.response, proof.target, proof.verb);
    if (createOnly) return ended;
    const later = at(proof.readbackExchange);
    assert.ok(later.id > ended.id);
    assert.equal(later.request.path, `/v1/${proof.target}`);
    assert.equal(later.derivedFrom, ended.id);
    if (proof.verb === "delete") {
      assert.equal(later.response.status, 404, "deleted resource still present");
      assert.equal(later.body.error?.code, 404);
      assert.equal(later.body.error?.status, "NOT_FOUND");
      assert.equal(typeof later.body.error?.message, "string");
    } else {
      assert.equal(later.response.status, 200);
      resource(later.body);
      resourceFields(later.body);
      for (const key of ["name", "uid", "createTime", "pubsubTopic", "state"])
        assert.equal(later.body[key], ended.body.response[key]);
    }
    return ended;
  };
  for (const proof of report.proofs) {
    assert.equal(proof.complete, true);
    if (proof.kind === "own-operation-terminal") terminal(proof);
    else if (proof.kind === "paired-own-operation-terminals") {
      const issued = at(proof.createIssuedExchange);
      const ended = terminal(
        {
          source: proof.createSource,
          issuedExchange: issued.id,
          terminalExchange: proof.createTerminalExchange,
          name: issued.body.name,
          target: proof.target,
          verb: "create",
        },
        true,
      );
      const start = at(proof.start.operationExchange),
        channel = at(proof.start.channelExchange);
      assert.ok(issued.id < start.id && start.id < proof.deleteIssuedExchange);
      assert.ok(issued.id < channel.id && channel.id < start.id, "unfinished start chronology");
      ownPoll(start, issued, proof.target, "create");
      assert.equal(start.derivedFrom, issued.id);
      assert.equal(channel.response.status, 200);
      assert.equal(channel.request.method, "GET");
      assert.equal(channel.request.path, `/v1/${proof.target}`);
      assert.equal(channel.derivedFrom, issued.id);
      assert.equal(channel.body.name, proof.target);
      unfinishedResource(channel.body);
      operation(start.body, proof.target, "create");
      assert.equal(start.body.name, issued.body.name);
      assert.equal(start.body.done, false);
      resourceIdentity(channel.body);
      for (const key of ["name", "uid", "createTime"])
        assert.equal(ended.body.response[key], channel.body[key]);
      assert.notEqual(proof.deleteTerminal.name, issued.body.name);
      assert.equal(proof.deleteTerminal.issuedExchange, proof.deleteIssuedExchange);
      assert.deepEqual(proof.deleteTerminal.source, proof.deleteSource);
      terminal(proof.deleteTerminal);
    } else {
      assert.equal(proof.kind, "own-cursor-walk", "unknown lifecycle proof");
      const before = at(proof.before),
        after = at(proof.after);
      const collection = before.request.path.slice(4);
      const expected = inventoryRows(before, collection),
        final = inventoryRows(after, collection);
      if (nativeInventories) {
        const native = nativeInventories[proof.key];
        assert.ok(native, "missing native inventory");
        assert.deepEqual(
          [...expected.keys()].sort(),
          native.map((channel) => channel.name).sort(),
          "native inventory membership",
        );
        for (const channel of native)
          assert.deepEqual(
            Object.keys(expected.get(channel.name)),
            Object.keys(channel),
            "native resource fields",
          );
      }
      assert.ok(isDeepStrictEqual(expected, final), "inventory changed");
      assert.equal(proof.resourceCount, expected.size, "inventory count");
      assert.ok(Array.isArray(proof.pages) && proof.pages.length, "missing walk pages");
      const seen = new Set(),
        uids = new Set(),
        tokens = new Set();
      let previous = null;
      for (const id of proof.pages) {
        const page = at(id),
          params = new URLSearchParams(page.request.path.split("?")[1] ?? "");
        assert.ok(before.id < id && id < after.id);
        assert.equal(page.request.path.split("?")[0], `/v1/${collection}`);
        assert.equal(page.response.status, 200);
        assert.equal(page.derivedFrom, previous?.id ?? null, "own cursor issuer");
        assert.equal(
          params.get("pageToken"),
          previous?.body.nextPageToken ?? null,
          "own cursor value",
        );
        const size = Number(params.get("pageSize"));
        assert.ok(Number.isSafeInteger(size) && size > 0);
        assert.ok(page.body.channels.length > 0 && page.body.channels.length <= size);
        assert.deepEqual(
          Object.keys(page.body),
          Object.hasOwn(page.body, "nextPageToken") ? ["channels", "nextPageToken"] : ["channels"],
        );
        for (const channel of page.body.channels) {
          resource(channel);
          assert.ok(!seen.has(channel.name) && !uids.has(channel.uid), "duplicate walk member");
          assert.deepEqual(channel, expected.get(channel.name), "foreign walk member");
          seen.add(channel.name);
          uids.add(channel.uid);
        }
        if (Object.hasOwn(page.body, "nextPageToken")) {
          const token = page.body.nextPageToken;
          assert.match(token, /^[A-Za-z0-9_-]+$/);
          assert.equal(Buffer.from(token, "base64url").toString("base64url"), token);
          assert.ok(!tokens.has(token));
          tokens.add(token);
        }
        previous = page;
      }
      assert.equal(Object.hasOwn(previous.body, "nextPageToken"), false, "walk nonterminal tail");
      assert.equal(seen.size, expected.size, "missing walk member");
    }
  }
  // Setup CREATEs are collected to terminal before selected case proofs; validate them identically.
  for (const issued of exchanges.filter(
    (row) =>
      !accounted.has(row.id) &&
      ["POST", "DELETE"].includes(row.request.method) &&
      row.derivedFrom === null,
  )) {
    const target = issued.body.metadata?.target,
      verb = issued.body.metadata?.verb;
    const ended = exchanges.find(
      (row) =>
        row.id > issued.id &&
        row.derivedFrom === issued.id &&
        row.body.name === issued.body.name &&
        row.body.done === true,
    );
    assert.ok(ended, "unproved setup terminal");
    const later = exchanges.find((row) => row.derivedFrom === ended.id && row.id > ended.id);
    assert.ok(later, "unproved setup readback");
    terminal({
      source: issued.source,
      issuedExchange: issued.id,
      terminalExchange: ended.id,
      readbackExchange: later.id,
      name: issued.body.name,
      target,
      verb,
    });
  }
  assert.equal(accounted.size, exchanges.length, "unknown or detached retained exchange");
  return true;
}

/** Reuse collector predicates for every retained successful raw lifecycle answer. */
export function validateLifecycleAnswer(native, actual, wire, nativeResources) {
  assert.equal(native.response.status, 200);
  assert.equal(actual.status, 200, "successful lifecycle status");
  const body = actual.body;
  if (["createChannel", "deleteChannel", "getOperation"].includes(native.op)) {
    const expected = native.response.body;
    operation(body, expected.metadata.target, expected.metadata.verb);
    if (native.op === "getOperation")
      assert.equal(wire.path.split("?")[0], `/v1/${body.name}`, "raw own operation identity");
    if (body.done) {
      const original = nativeResources.find(
        (resource) => resource.name === expected.metadata.target && resource.state === "ACTIVE",
      );
      if (expected.metadata.verb === "create")
        assert.ok(original, "missing bound terminal authority");
      terminalResource(
        body.response,
        expected.metadata.target,
        expected.metadata.verb,
        original?.pubsubTopic.split("/")[1],
      );
    }
  } else if (native.op === "getChannel") {
    assert.equal(body.name, native.response.body.name, "raw channel identity");
    if (Object.hasOwn(body, "state")) {
      const original = nativeResources.find(
        (candidate) => candidate.name === body.name && candidate.state === "ACTIVE",
      );
      assert.ok(original, "missing bound channel authority");
      resource(body, "ACTIVE", original.pubsubTopic.split("/")[1]);
      assert.deepEqual(Object.keys(body), [
        "name",
        "uid",
        "createTime",
        "updateTime",
        "pubsubTopic",
        "state",
      ]);
    } else unfinishedResource(body);
  } else {
    assert.equal(native.op, "listChannels");
    assert.ok(Array.isArray(body.channels), "raw list channels field");
    assert.deepEqual(
      Object.keys(body),
      Object.hasOwn(body, "nextPageToken") ? ["channels", "nextPageToken"] : ["channels"],
    );
    for (const channel of body.channels) {
      if (Object.hasOwn(channel, "state")) {
        const original = nativeResources.find(
          (candidate) => candidate.name === channel.name && candidate.state === "ACTIVE",
        );
        assert.ok(original, "raw list original identity");
        resource(channel, "ACTIVE", original.pubsubTopic.split("/")[1]);
      } else {
        assert.ok(
          nativeResources.some((candidate) => candidate.name === channel.name),
          "foreign unfinished list member",
        );
        unfinishedResource(channel);
      }
      const scope = native.request.path.split("?")[0].slice(4);
      const requested = scope.split("/"),
        actual = channel.name.split("/");
      assert.equal(actual.length, requested.length + 1, "raw list resource path");
      for (let i = 0; i < requested.length; i++)
        if (!(i === 3 && requested[i] === "-"))
          assert.equal(actual[i], requested[i], "raw list resource authority");
    }
    const params = new URLSearchParams(native.request.path.split("?")[1] ?? "");
    if (params.has("pageSize") && Number(params.get("pageSize")) > 0)
      assert.ok(body.channels.length <= Number(params.get("pageSize")), "raw list upper bound");
    if (Object.hasOwn(body, "nextPageToken")) {
      assert.match(body.nextPageToken, /^[A-Za-z0-9_-]+$/);
      assert.equal(
        Buffer.from(body.nextPageToken, "base64url").toString("base64url"),
        body.nextPageToken,
      );
      assert.ok(body.channels.length > 0, "raw token without members");
    }
  }
  return true;
}
