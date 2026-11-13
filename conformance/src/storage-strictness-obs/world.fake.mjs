import { CORS } from "./guard.mjs";

// Synthetic answers exercise the recorder; they are never production evidence.
export function createFakeWorld(
  target,
  { faults = {}, applyBeforeFault = [], clock = { now: Date.now } } = {},
) {
  const buckets = new Map([[target.defaultBucket, { name: target.defaultBucket, location: "US" }]]);
  const objects = new Map();
  const log = [];
  const json = (status, value) => ({
    status,
    headers: { "content-type": "application/json; charset=UTF-8" },
    body: Buffer.from(JSON.stringify(value)),
  });
  const empty = (status, headers = {}) => ({ status, headers, body: Buffer.alloc(0) });
  const missing = () =>
    json(404, {
      error: {
        code: 404,
        message: "The specified bucket does not exist.",
        errors: [
          { message: "The specified bucket does not exist.", domain: "global", reason: "notFound" },
        ],
      },
    });
  function perform(r) {
    const url = new URL(r.url);
    const path = url.pathname;
    const bucket =
      /\/(?:storage\/v1|upload\/storage\/v1|v0)\/b\/([^/]+)/.exec(path)?.[1] ?? path.split("/")[1];
    const name = path.includes("/o/")
      ? decodeURIComponent(path.split("/o/")[1].split("/")[0])
      : (url.searchParams.get("name") ?? path.split("/").slice(2).join("/"));
    const resource = `/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`;
    if (r.case === "W1") {
      if (buckets.has(target.tempBucket))
        return json(409, { error: { code: 409, message: "Already exists" } });
      const body = JSON.parse(r.body);
      buckets.set(body.name, body);
      return json(200, body);
    }
    if (!buckets.has(bucket)) return missing();
    if (r.case === "F1") return json(403, { error: { code: 403, message: "Invalid token" } });
    if (r.case === "A13" || r.case === "A14")
      return json(412, { error: { code: 412, message: "Bucket is not linked to Firebase" } });
    if (r.case === "A6" || r.case === "A7") return missing();
    if (r.method === "OPTIONS") {
      const rules = buckets.get(bucket).cors ?? [];
      const h = r.headers;
      const rule = rules.find(
        (entry) =>
          (entry.origin.includes("*") || entry.origin.includes(h.origin)) &&
          entry.method.includes(h["access-control-request-method"]) &&
          (!h["access-control-request-headers"] ||
            entry.responseHeader.includes("*") ||
            entry.responseHeader.some(
              (header) => header.toLowerCase() === h["access-control-request-headers"],
            )),
      );
      return empty(
        200,
        rule
          ? {
              "access-control-allow-origin": rule.origin.includes("*") ? "*" : h.origin,
              "access-control-allow-methods": h["access-control-request-method"],
              "access-control-max-age": String(rule.maxAgeSeconds ?? 3600),
              ...(h["access-control-request-headers"]
                ? { "access-control-allow-headers": h["access-control-request-headers"] }
                : {}),
            }
          : {},
      );
    }
    if (r.method === "PATCH") {
      delete buckets.get(bucket).cors;
      return json(200, {});
    }
    if (r.action === "create") {
      objects.set(r.resource, { name, bucket, size: "4" });
      return json(200, objects.get(r.resource));
    }
    if (path.endsWith("/o")) {
      const prefix = url.searchParams.get("prefix") ?? "";
      return json(200, {
        items: [...objects.values()].filter(
          (object) => object.bucket === bucket && object.name.startsWith(prefix),
        ),
      });
    }
    if (/^\/storage\/v1\/b\/[^/]+$/.test(path)) {
      if (r.method === "DELETE") {
        if ([...objects.values()].some((object) => object.bucket === bucket))
          return json(409, { error: { code: 409, message: "Bucket not empty" } });
        buckets.delete(bucket);
        return empty(204);
      }
      return json(200, buckets.get(bucket));
    }
    if (!objects.has(resource)) return missing();
    if (r.method === "DELETE") {
      objects.delete(resource);
      return empty(204);
    }
    if (
      url.searchParams.get("alt") === "media" ||
      (!path.startsWith("/storage/") && !path.startsWith("/v0/"))
    )
      return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("fire") };
    return json(200, objects.get(resource));
  }
  return {
    buckets,
    objects,
    log,
    cors: CORS,
    async net(request) {
      log.push({ ...request, at: clock.now() });
      const fault = faults[request.case];
      const answer =
        fault === undefined || applyBeforeFault.includes(request.case)
          ? perform(request)
          : undefined;
      if (fault === "transport") throw new Error("synthetic transport failure");
      if (typeof fault === "function") return fault(request, { buckets, objects, answer });
      return fault === undefined ? answer : { headers: {}, body: Buffer.alloc(0), ...fault };
    },
  };
}
