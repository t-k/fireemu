// A fake production Pub/Sub REST frontend on virtual time, with the negative cache as a set of
// parameters. It answers the request shapes of the program with the recorded bodies and latencies
// (a slow 404 is about 300 ms, a cached one 20 ms, a create 5-9 s, a delete 3 s). It exists so the
// recorder, its cleanup and its judge are tested end to end against every alternative of the open
// questions, and so an unexpected request shape is refused as production would.

export const DEFAULT_WORLD = Object.freeze({
  ttl: 9600,
  anchor: "start", // "start" | "completion"
  armers: ["getSub", "getSnap", "putSub", "putSnap"],
  absentServed: true,
  bodyClear: "other", // "none" | "other" | "all"
  served: ["getSub", "getSnap"],
  getHitRearms: false,
  deleteHitRearms: false,
  positiveExempt: true,
  exemptTtl: 9600,
  keyIncludesQuery: false,
  kindsShared: false,
  grpcShared: false,
  connAffinity: false,
  existingMissingTopic: 404, // status of a create of an existing name with a missing topic
});

const LATENCY = {
  slow: 300,
  fast: 20,
  createSub: 5000,
  createSnap: 8000,
  createTopic: 600,
  delete: 3000,
};
const error = (status, code, message) => ({
  status,
  bodyText: JSON.stringify({ error: { code: status, message, status: code } }),
});
const notFound = (id) => error(404, "NOT_FOUND", `Resource not found (resource=${id}).`);

export function createWorld({ clock, params = {}, faults = new Map() } = {}) {
  const P = { ...DEFAULT_WORLD, ...params };
  const armers = new Set(P.armers);
  const served = new Set(P.served);
  const exists = { topic: new Map(), subscription: new Map(), snapshot: new Map() };
  const armed = new Map(); // key -> {at, conn}
  const okGet = new Map();
  const log = [];
  let n = 0;

  const parse = (path) => {
    const [pathname, query = ""] = path.split("?");
    const m =
      /^\/v1\/projects\/([^/]+)\/(topics|subscriptions|snapshots)(?:\/([^/:]+)(?::(\w+))?)?$/.exec(
        pathname,
      );
    if (!m) return null;
    const kind = { topics: "topic", subscriptions: "subscription", snapshots: "snapshot" }[m[2]];
    return { project: m[1], kind, id: m[3], verb: m[4], query: query ? `?${query}` : "" };
  };
  const opOf = (req, p) => {
    if (req.grpc) return "grpcGetSub";
    if (p.id === undefined)
      return p.kind === "subscription" && req.method === "GET" ? "listSub" : "list";
    if (p.verb) return `${req.method}:${p.verb}`;
    const noun = { subscription: "Sub", snapshot: "Snap", topic: "Topic" }[p.kind];
    const verb = { GET: "get", PUT: "put", DELETE: "delete", PATCH: "patch" }[req.method];
    return `${verb}${noun}`;
  };
  const armerName = (op) =>
    ({ "POST:pull": "pullSub", "GET:getIamPolicy": "getIamSub", "POST:seek": "seekSub" })[op] ?? op;

  async function send(req, { conn = "pool", timeoutMs = 30000 } = {}) {
    const index = ++n;
    const startedAt = clock.now();
    const p = req.grpc
      ? { kind: "subscription", id: req.path.split("/").pop(), query: "" }
      : parse(req.path);
    const fault = faults.get(index);
    const finish = async (latency, result, extra = {}) => {
      await clock.sleep(latency);
      const headersAt = clock.now();
      log.push({
        index,
        op: req.method + " " + req.path,
        status: result.status,
        startedAt,
        latency,
      });
      return { startedAt, headersAt, completedAt: headersAt, ...result, ...extra };
    };
    if (!p) return finish(LATENCY.slow, error(404, "NOT_FOUND", "unknown resource"));
    const op = opOf(req, p);
    const kindKey = P.kindsShared ? "any" : p.kind;
    const key = `${kindKey}:${p.id}${P.keyIncludesQuery ? p.query : ""}`;
    const live = (e, t) =>
      e && t - e.at >= 0 && t - e.at < P.ttl && (!P.connAffinity || e.conn === conn);

    const run = () => {
      // Cached answer.
      const e = armed.get(key);
      const grpcOk = op !== "grpcGetSub" || P.grpcShared;
      const present = exists[p.kind].has(p.id);
      if (
        live(e, startedAt) &&
        (served.has(armerName(op)) ||
          (op === "grpcGetSub" && P.grpcShared && served.has("getSub"))) &&
        grpcOk &&
        (P.absentServed || present)
      ) {
        if (op.startsWith("get") && P.getHitRearms) armed.set(key, { at: startedAt, conn });
        if (op.startsWith("delete") && P.deleteHitRearms) armed.set(key, { at: startedAt, conn });
        return { latency: LATENCY.fast, result: notFound(p.id), fast: true };
      }
      let result;
      let latency = LATENCY.slow;
      const body = req.body ?? {};
      const topicOf = (name) => exists.topic.has(String(name).split("/").pop());
      switch (op) {
        case "putTopic":
          latency = LATENCY.createTopic;
          if (exists.topic.has(p.id))
            result = error(
              409,
              "ALREADY_EXISTS",
              "Resource already exists in the project (resource=" + p.id + ").",
            );
          else {
            exists.topic.set(p.id, {});
            result = {
              status: 200,
              bodyText: JSON.stringify({ name: `projects/${p.project}/topics/${p.id}` }),
            };
          }
          break;
        case "putSub": {
          const hasTopic = topicOf(body.topic);
          if (!hasTopic) result = notFound(String(body.topic).split("/").pop());
          else if (exists.subscription.has(p.id))
            result = error(
              409,
              "ALREADY_EXISTS",
              "Resource already exists in the project (resource=" + p.id + ").",
            );
          else {
            latency = LATENCY.createSub;
            exists.subscription.set(p.id, { labels: {} });
            result = {
              status: 200,
              bodyText: JSON.stringify({
                name: `projects/${p.project}/subscriptions/${p.id}`,
                topic: body.topic,
              }),
            };
          }
          if (!hasTopic && exists.subscription.has(p.id) && P.existingMissingTopic === 409)
            result = error(
              409,
              "ALREADY_EXISTS",
              "Resource already exists in the project (resource=" + p.id + ").",
            );
          break;
        }
        case "putSnap": {
          const hasSub = exists.subscription.has(String(body.subscription).split("/").pop());
          if (!hasSub) result = notFound(String(body.subscription).split("/").pop());
          else if (exists.snapshot.has(p.id))
            result = error(
              409,
              "ALREADY_EXISTS",
              "Resource already exists in the project (resource=" + p.id + ").",
            );
          else {
            latency = LATENCY.createSnap;
            exists.snapshot.set(p.id, {});
            result = {
              status: 200,
              bodyText: JSON.stringify({ name: `projects/${p.project}/snapshots/${p.id}` }),
            };
          }
          break;
        }
        case "getSub":
        case "getSnap":
        case "getTopic":
        case "grpcGetSub":
          result = exists[p.kind].has(p.id)
            ? {
                status: 200,
                bodyText: JSON.stringify({
                  name: `projects/${p.project}/${p.kind === "topic" ? "topics" : p.kind === "snapshot" ? "snapshots" : "subscriptions"}/${p.id}`,
                  labels: exists[p.kind].get(p.id).labels ?? undefined,
                }),
              }
            : notFound(p.id);
          break;
        case "deleteSub":
        case "deleteSnap":
        case "deleteTopic":
          if (exists[p.kind].delete(p.id)) {
            latency = LATENCY.delete;
            result = { status: 200, bodyText: "{}" };
          } else result = notFound(p.id);
          break;
        case "patchSub":
          if (exists.subscription.has(p.id)) {
            exists.subscription.get(p.id).labels = body.subscription?.labels ?? {};
            result = {
              status: 200,
              bodyText: JSON.stringify({
                name: `projects/${p.project}/subscriptions/${p.id}`,
                labels: body.subscription?.labels,
              }),
            };
          } else result = notFound(p.id);
          break;
        case "POST:pull":
        case "GET:getIamPolicy":
          result = exists.subscription.has(p.id) ? { status: 200, bodyText: "{}" } : notFound(p.id);
          break;
        case "POST:seek":
          result = notFound(String(body.snapshot).split("/").pop());
          break;
        case "listSub":
        case "list": {
          const noun = { subscription: "subscriptions", snapshot: "snapshots", topic: "topics" }[
            p.kind
          ];
          const names = [...exists[p.kind].keys()].map((id) => ({
            name: `projects/${p.project}/${noun}/${id}`,
          }));
          result = { status: 200, bodyText: JSON.stringify(names.length ? { [noun]: names } : {}) };
          break;
        }
        default:
          result = error(400, "INVALID_ARGUMENT", "unsupported request");
      }
      return { latency, result, fast: false, op, present };
    };

    const out = run();
    // Arming and clearing apply to the key of the URL resource.
    if (!out.fast) {
      const status = out.result.status;
      if (status === 200 && (op === "getSub" || op === "getSnap")) okGet.set(key, startedAt);
      if (status === 404 && armers.has(armerName(op))) {
        const at = P.anchor === "start" ? startedAt : startedAt + out.latency;
        const exempt =
          P.positiveExempt &&
          okGet.has(key) &&
          startedAt - okGet.get(key) >= 0 &&
          startedAt - okGet.get(key) < P.exemptTtl;
        if (!live(armed.get(key), startedAt) && !exempt) armed.set(key, { at, conn });
      }
      if (status === 200 && op === "putSub" && req.body?.name && P.bodyClear !== "none") {
        const named = String(req.body.name).split("/").pop();
        if (P.bodyClear === "all" || named !== p.id) armed.delete(`${kindKey}:${named}`);
      }
    }
    if (fault === "timeout") {
      await clock.sleep(timeoutMs);
      log.push({ index, op: req.method + " " + req.path, fault });
      return { startedAt, failure: "timeout", completedAt: clock.now() };
    }
    if (fault === "status500")
      return finish(out.latency, {
        status: 500,
        bodyText: JSON.stringify({ error: { code: 500, message: "internal", status: "INTERNAL" } }),
      });
    if (fault === "status302") return finish(out.latency, { status: 302, bodyText: "" });
    if (fault === "garbage")
      return finish(out.latency, { status: out.result.status, bodyText: "<html>" });
    return finish(out.latency, out.result);
  }
  return { send, state: exists, log, armed };
}

/** A virtual monotonic clock: sleeping advances time at once. */
export function virtualClock(start = 0) {
  let t = start;
  return {
    now: () => t,
    async sleep(ms) {
      t += Math.max(0, ms);
    },
    async sleepUntil(at) {
      if (at > t) t = at;
    },
  };
}
