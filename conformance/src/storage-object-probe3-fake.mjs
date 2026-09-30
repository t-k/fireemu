// A stateful fake of production for the probe-v3 tests, answering in the shapes production has
// recorded (see `recorded/`). Not a test file: the tests import it.

export const BUCKET = "fireemu-oracle-query.firebasestorage.app";

export const json = (status, body, headers = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=UTF-8", ...headers },
  });
const notFound = (name) =>
  json(404, {
    error: { code: 404, message: `No such object: ${BUCKET}/${name}`, errors: [] },
  });

/**
 * A stateful production. Options:
 * - `odd`: every answer before the cleanup starts is a plain-text 200 that says nothing (the
 *   effects still happen), and the sessions carry no URL;
 * - `rewriteCalls`: how many rewriteTo calls it takes (the first ones answer `done: false`);
 * - `noGeneration`: a metadata read answers 200 without a generation;
 * - `conditionalDeleteFails`: a conditional DELETE answers 412 and keeps the object;
 * - `deleteFails`: any DELETE of that object answers 500 and keeps it;
 * - `failAt`: the nth request throws like a lost connection;
 * - `strays`: that many objects already under `strayPrefix` (the run did not create them);
 * - `listLeaksOutside`: a list of the cleanup also names an object outside the prefix asked for;
 * - `endlessPages`: a list always has another page; `emptyToken`: its next-page token is "";
 * - `rewriteNoToken`, `rewriteEmptyToken`: the first rewrite call is not done and has no token,
 *   or an empty one; `manyTokens`: create_token adds two tokens;
 * - `listOnlyOutside`: once the cleanup has started, a list names only an object outside the prefix;
 * - `listItemsOdd`: once the cleanup has started, a list says `items` is that value;
 * - `cleanupMetadata`: the status and body of an object metadata read once the cleanup has started.
 */
export function production(options = {}) {
  const store = new Map();
  const calls = [];
  const history = [];
  let rewriteSeen = 0;
  let generation = 1_000_000;
  let cleanup = false;
  const sessions = new Map();
  const tokens = new Map();
  const object = (name) => store.get(name);
  for (let i = 0; i < (options.strays ?? 0); i++)
    store.set(`${options.strayPrefix ?? ""}stray-${i}.bin`, { generation: `${900 + i}`, size: 1 });
  const resource = (name, o) => ({
    kind: "storage#object",
    bucket: BUCKET,
    name,
    generation: options.noGeneration && cleanup ? undefined : o.generation,
    metageneration: "2",
    size: String(o.size),
  });
  const put = (name, size) => {
    const o = { generation: `${++generation}`, size };
    store.set(name, o);
    history.push({ name, generation: o.generation });
    return o;
  };
  const answer = (real) =>
    options.odd && !cleanup ? new Response("nothing", { status: 200 }) : real;

  async function fetchImpl(url, init) {
    const href = String(url);
    calls.push({ href, method: init.method, headers: new Headers(init.headers), body: init.body });
    if (options.failAt === calls.length) throw new TypeError("fetch failed");
    const u = new URL(href);
    const method = init.method;
    const path = u.pathname;
    const name = u.searchParams.get("name");
    const command = new Headers(init.headers).get("x-goog-upload-command");
    const size = init.body ? init.body.length : 0;

    // ---- GCS uploads ----
    if (path.startsWith("/upload/storage/v1/b/") && method === "POST") {
      const type = u.searchParams.get("uploadType");
      if (type === "resumable") {
        const id = `s${sessions.size + 1}`;
        sessions.set(id, { name, received: 0 });
        return answer(
          new Response("", {
            status: 200,
            headers: options.odd
              ? {}
              : {
                  location: `${href}&upload_id=${id}`,
                  "content-type": "text/plain; charset=utf-8",
                },
          }),
        );
      }
      const o = put(name, size);
      return answer(json(200, resource(name, o)));
    }
    if (path.startsWith("/upload/storage/v1/b/") && method === "PUT") {
      const session = sessions.get(u.searchParams.get("upload_id"));
      const range = new Headers(init.headers).get("content-range");
      if (range?.startsWith("bytes */")) return answer(new Response(null, { status: 308 }));
      session.received += size;
      if (session.received >= 262147) {
        const o = put(session.name, session.received);
        return answer(json(200, resource(session.name, o)));
      }
      return answer(new Response(null, { status: 308, headers: { range: "bytes=0-262143" } }));
    }
    // ---- Firebase ----
    if (path === `/v0/b/${BUCKET}/o` && method === "POST") {
      if (command === "start") {
        const id = `f${sessions.size + 1}`;
        sessions.set(id, { name, received: 0 });
        return answer(
          new Response("", {
            status: 200,
            headers: options.odd
              ? {}
              : {
                  "x-goog-upload-status": "active",
                  "x-goog-upload-url": `${href}&upload_id=${id}&upload_protocol=resumable`,
                },
          }),
        );
      }
      const id = u.searchParams.get("upload_id");
      if (id) {
        const session = sessions.get(id);
        if (command === "query")
          return answer(
            new Response(null, {
              status: 200,
              headers: {
                "x-goog-upload-status": "active",
                "x-goog-upload-size-received": String(session.received),
              },
            }),
          );
        session.received += size;
        if (command.includes("finalize")) {
          const o = put(session.name, session.received);
          return answer(
            json(
              200,
              { name: session.name, bucket: BUCKET, generation: o.generation },
              {
                "x-goog-upload-status": "final",
              },
            ),
          );
        }
        return answer(
          new Response(null, { status: 200, headers: { "x-goog-upload-status": "active" } }),
        );
      }
      const o = put(name, size);
      tokens.set(name, ["t1"]);
      return answer(
        json(200, { name, bucket: BUCKET, generation: o.generation, downloadTokens: "t1" }),
      );
    }
    if (path.startsWith(`/v0/b/${BUCKET}/o/`) && method === "POST") {
      const target = decodeURIComponent(path.split("/o/")[1]);
      const list = tokens.get(target) ?? [];
      if (u.searchParams.get("create_token") === "true") {
        list.push(`t${list.length + 1}`);
        if (options.manyTokens) list.push(`t${list.length + 1}`);
        tokens.set(target, list);
        return answer(json(200, { name: target, bucket: BUCKET, downloadTokens: list.join(",") }));
      }
      const del = u.searchParams.get("delete_token");
      tokens.set(
        target,
        list.filter((value) => value !== del),
      );
      return answer(
        json(200, { name: target, bucket: BUCKET, downloadTokens: tokens.get(target).join(",") }),
      );
    }
    // ---- GCS objects ----
    if (path.startsWith(`/storage/v1/b/${BUCKET}/o/`)) {
      const rest = path.split("/o/").slice(1).join("/o/");
      const parts = rest.split("/");
      const target = decodeURIComponent(parts[0]);
      if (method === "POST" && (parts[1] === "copyTo" || parts[1] === "rewriteTo")) {
        const destination = decodeURIComponent(path.split("/o/").at(-1));
        const source = object(target);
        if (parts[1] === "rewriteTo") {
          const calls_ = ++rewriteSeen;
          if (calls_ < (options.rewriteCalls ?? 1))
            return answer(
              json(200, {
                kind: "storage#rewriteResponse",
                done: false,
                ...(options.rewriteNoToken
                  ? {}
                  : { rewriteToken: options.rewriteEmptyToken ? "" : `rt${calls_}` }),
              }),
            );
        }
        const o = put(destination, source?.size ?? 0);
        return answer(
          json(200, {
            kind: "storage#rewriteResponse",
            done: true,
            resource: resource(destination, o),
          }),
        );
      }
      if (method === "DELETE") {
        const o = object(target);
        if (options.deleteFails === target) return json(500, { error: { code: 500 } });
        if (!o) return notFound(target);
        if (u.searchParams.get("ifGenerationMatch") && options.conditionalDeleteFails)
          return json(412, { error: { code: 412 } });
        store.delete(target);
        return new Response(null, { status: 204, headers: { "content-type": "application/json" } });
      }
      if (method === "GET" && cleanup && options.cleanupMetadata)
        return new Response(options.cleanupMetadata.body, {
          status: options.cleanupMetadata.status,
          headers: { "content-type": "application/json" },
        });
      if (method === "GET") {
        const o = object(target);
        if (!o) return answer(notFound(target));
        return answer(json(200, resource(target, o)));
      }
    }
    // ---- lists ----
    if (path === `/storage/v1/b/${BUCKET}/o` && method === "GET") {
      const prefix = u.searchParams.get("prefix");
      const max = Number(u.searchParams.get("maxResults") ?? 1000);
      const start = Number(u.searchParams.get("pageToken") ?? 0);
      const names = [...store.keys()].filter((n) => n.startsWith(prefix)).toSorted();
      if (u.searchParams.get("maxResults") === "1000") cleanup = true;
      const page = names.slice(start, start + max);
      const next =
        options.endlessPages || start + max < names.length
          ? { nextPageToken: options.emptyToken ? "" : String(start + max) }
          : {};
      if (u.searchParams.get("delimiter")) cleanup = true;
      if (cleanup && options.listOnlyOutside)
        return json(200, {
          kind: "storage#objects",
          items: [{ name: "storage-object/other/x.bin", bucket: BUCKET }],
        });
      if (cleanup && options.listItemsOdd !== undefined)
        return json(200, { kind: "storage#objects", items: options.listItemsOdd });
      return cleanup && !options.odd
        ? json(200, {
            kind: "storage#objects",
            items: [
              ...page.map((n) => resource(n, object(n))),
              ...(options.listLeaksOutside && page.length
                ? [{ name: "storage-object/other/x.bin", bucket: BUCKET }]
                : []),
            ],
            ...next,
          })
        : answer(
            json(200, {
              kind: "storage#objects",
              ...(page.length ? { items: page.map((n) => resource(n, object(n))) } : {}),
              ...next,
            }),
          );
    }
    return json(400, { error: { code: 400, message: "unexpected request" } });
  }
  return {
    fetchImpl,
    store,
    calls,
    history,
    startCleanup: () => {
      cleanup = true;
    },
  };
}
