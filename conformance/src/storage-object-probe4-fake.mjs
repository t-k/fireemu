// A stateful fake of production for the probe-v4 tests: an object store that refuses what the
// probe asks it to refuse, in the shapes production answers with, and, when `acceptRefused` is set,
// one that wrongly accepts every write it should have refused. Not a test file: the tests import it.

export const BUCKET = "fireemu-oracle-query.firebasestorage.app";

export const json = (status, body, headers = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=UTF-8", ...headers },
  });
const fail = (code, message) => json(code, { error: { code, message, errors: [] } });

/**
 * Options:
 * - `acceptRefused`: every write that should be refused is accepted and applied (deletes delete,
 *   copies of a missing source create their destination, wrong-offset chunks complete objects);
 * - `odd`: every answer before the cleanup starts is a plain-text 200 that says nothing (the effects
 *   still happen), and the sessions carry no URL;
 * - `failAt`: the nth request throws like a lost connection;
 * - `noGeneration`, `deleteFails`, `strays`, `strayPrefix`: as in the probe-v3 fake;
 * - `noToken`: a Firebase list has no next-page token.
 */
export function production(options = {}) {
  const store = new Map();
  const calls = [];
  const history = [];
  const sessions = new Map();
  let generation = 2_000_000;
  let cleanup = false;
  for (let i = 0; i < (options.strays ?? 0); i++)
    store.set(`${options.strayPrefix ?? ""}stray-${i}.bin`, {
      generation: `${900 + i}`,
      metageneration: 1,
      size: 1,
    });
  const resource = (name, o) => ({
    kind: "storage#object",
    bucket: BUCKET,
    name,
    generation: options.noGeneration && cleanup ? undefined : o.generation,
    metageneration: String(o.metageneration),
    size: String(o.size),
  });
  const put = (name, size) => {
    const o = { generation: `${(generation += 1000)}`, metageneration: 1, size };
    store.set(name, o);
    history.push({ name, generation: o.generation });
    return o;
  };
  const answer = (real) =>
    options.odd && !cleanup ? new Response("nothing", { status: 200 }) : real;

  /** The preconditions of a write on an existing object; null when they hold. */
  function refused(query, o) {
    if (options.acceptRefused) return null;
    const number = (key) => query.get(key);
    for (const key of ["ifGenerationMatch", "ifMetagenerationMatch", "ifGenerationNotMatch"]) {
      const value = number(key);
      if (value !== null && !/^(0|[1-9][0-9]*)$/.test(value))
        return fail(400, `Invalid value for ${key}`);
    }
    const match = number("ifGenerationMatch");
    if (match !== null && match !== o.generation) return fail(412, "Precondition Failed");
    const metaMatch = number("ifMetagenerationMatch");
    if (metaMatch !== null && metaMatch !== String(o.metageneration))
      return fail(412, "Precondition Failed");
    const notMatch = number("ifGenerationNotMatch");
    if (notMatch !== null && notMatch === o.generation) return fail(412, "Precondition Failed");
    return null;
  }

  async function fetchImpl(url, init) {
    const href = String(url);
    calls.push({ href, method: init.method, headers: new Headers(init.headers), body: init.body });
    if (options.failAt === calls.length) throw new TypeError("fetch failed");
    const u = new URL(href);
    const q = u.searchParams;
    const method = init.method;
    const path = u.pathname;
    const size = init.body ? init.body.length : 0;
    const command = new Headers(init.headers).get("x-goog-upload-command");

    // ---- GCS uploads ----
    if (path.startsWith("/upload/storage/v1/b/") && method === "POST") {
      if (q.get("uploadType") === "resumable") {
        const id = `s${sessions.size + 1}`;
        sessions.set(id, { name: q.get("name"), received: 0, open: true });
        return answer(
          new Response("", {
            status: 200,
            headers: options.odd ? {} : { location: `${href}&upload_id=${id}` },
          }),
        );
      }
      const name = q.get("name");
      const o = store.get(name);
      if (o) {
        const no = refused(q, o);
        if (no) return answer(no);
      } else if (
        q.get("ifGenerationMatch") !== null &&
        q.get("ifGenerationMatch") !== "0" &&
        !options.acceptRefused
      )
        return answer(fail(412, "Precondition Failed"));
      const made = put(name, size);
      return answer(json(200, resource(name, made)));
    }
    if (path.startsWith("/upload/storage/v1/b/") && method === "PUT") {
      const session = sessions.get(q.get("upload_id"));
      if (!session) return answer(fail(404, "Not Found"));
      if (!session.open) return answer(new Response(null, { status: 499 }));
      const range = new Headers(init.headers).get("content-range") ?? "";
      if (range.startsWith("bytes */")) return answer(new Response(null, { status: 308 }));
      const start = Number(/^bytes (\d+)-/.exec(range)?.[1] ?? 0);
      if (start !== session.received && !options.acceptRefused)
        return answer(
          fail(
            400,
            "Invalid request. According to the Content-Range header, the upload offset is wrong.",
          ),
        );
      session.received += size;
      if (options.acceptRefused) {
        const made = put(session.name, session.received);
        session.open = false;
        return answer(json(200, resource(session.name, made)));
      }
      return answer(new Response(null, { status: 308 }));
    }
    if (path.startsWith("/upload/storage/v1/b/") && method === "DELETE") {
      const session = sessions.get(q.get("upload_id"));
      if (!session) return answer(fail(404, "Not Found"));
      session.open = false;
      return answer(
        json(499, { error: { code: 499, message: "clientClosedRequest", errors: [] } }),
      );
    }
    // ---- Firebase ----
    if (path === `/v0/b/${BUCKET}/o` && method === "POST") {
      if (command === "start") {
        const id = `f${sessions.size + 1}`;
        sessions.set(id, { name: q.get("name"), received: 0, open: true });
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
      const id = q.get("upload_id");
      if (id) {
        const session = sessions.get(id);
        if (!session) return answer(fail(404, "Not Found"));
        if (command === "cancel") {
          session.open = false;
          return answer(
            new Response(null, { status: 200, headers: { "x-goog-upload-status": "cancelled" } }),
          );
        }
        const offset = Number(new Headers(init.headers).get("x-goog-upload-offset") ?? 0);
        if (offset !== session.received && !options.acceptRefused)
          return answer(
            new Response("Invalid offset", {
              status: 400,
              headers: { "content-type": "text/plain" },
            }),
          );
        session.received += size;
        return answer(
          new Response(null, { status: 200, headers: { "x-goog-upload-status": "active" } }),
        );
      }
      // A simple Firebase upload (the probe's `firebase-upload-zero-present`): v0 takes no precondition.
      const made = put(q.get("name"), size);
      return answer(
        json(200, { name: q.get("name"), bucket: BUCKET, generation: made.generation }),
      );
    }
    if (path.startsWith(`/v0/b/${BUCKET}/o/`) && method === "PATCH") {
      const name = decodeURIComponent(path.split("/o/")[1]);
      const o = store.get(name);
      if (!o) return answer(fail(404, "Not Found."));
      // v0 ignores the GCS preconditions, so the metadata changes.
      o.metageneration += 1;
      return answer(json(200, { name, bucket: BUCKET, generation: o.generation }));
    }
    if (path === `/v0/b/${BUCKET}/o` && method === "GET") {
      const prefix = q.get("prefix");
      const max = Number(q.get("maxResults") ?? 1000);
      const start = Number(q.get("pageToken") ?? 0);
      const names = [...store.keys()].filter((n) => n.startsWith(prefix)).toSorted();
      const page = names.slice(start, start + max);
      const next =
        start + max < names.length && !options.noToken
          ? { nextPageToken: String(start + max) }
          : {};
      const response = answer(
        json(200, { prefixes: [], items: page.map((name) => ({ name, bucket: BUCKET })), ...next }),
      );
      // The last recording request of the probe: from here on the answers are honest.
      if (!q.has("pageToken")) cleanup = true;
      return response;
    }
    // ---- GCS objects ----
    if (path.startsWith(`/storage/v1/b/${BUCKET}/o/`)) {
      const parts = path.split("/o/").slice(1).join("/o/").split("/");
      const name = decodeURIComponent(parts[0]);
      const o = store.get(name);
      if (method === "POST" && (parts[1] === "copyTo" || parts[1] === "rewriteTo")) {
        const destination = decodeURIComponent(path.split("/o/").at(-1));
        if (!o && !options.acceptRefused)
          return answer(fail(404, `No such object: ${BUCKET}/${name}`));
        const live = store.get(destination);
        if (live && !options.acceptRefused && q.get("ifGenerationMatch") === "0")
          return answer(fail(412, "Precondition Failed"));
        const made = put(destination, o?.size ?? 0);
        return answer(
          json(200, {
            kind: "storage#rewriteResponse",
            done: true,
            resource: resource(destination, made),
          }),
        );
      }
      if (method === "PATCH" || method === "PUT") {
        if (!o) return answer(fail(404, `No such object: ${BUCKET}/${name}`));
        const no = refused(q, o);
        if (no) return answer(no);
        o.metageneration += 1;
        return answer(json(200, resource(name, o)));
      }
      if (method === "DELETE") {
        if (options.deleteFails === name) return json(500, { error: { code: 500 } });
        if (!o) return answer(fail(404, `No such object: ${BUCKET}/${name}`));
        const no = refused(q, o);
        if (no) return answer(no);
        store.delete(name);
        return new Response(null, { status: 204, headers: { "content-type": "application/json" } });
      }
      if (method === "GET") {
        if (!o) return answer(fail(404, `No such object: ${BUCKET}/${name}`));
        return answer(json(200, resource(name, o)));
      }
    }
    // ---- GCS lists ----
    if (path === `/storage/v1/b/${BUCKET}/o` && method === "GET") {
      if (q.get("maxResults") === "1000") cleanup = true;
      const prefix = q.get("prefix");
      let names = [...store.keys()].filter((n) => n.startsWith(prefix)).toSorted();
      const startOffset = q.get("startOffset");
      const endOffset = q.get("endOffset");
      if (startOffset) names = names.filter((n) => n >= startOffset);
      if (endOffset) names = names.filter((n) => n < endOffset);
      const glob = q.get("matchGlob");
      if (glob) {
        const re = new RegExp(
          `^${glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*")}$`,
        );
        names = names.filter((n) => re.test(n));
      }
      const body = {
        kind: "storage#objects",
        ...(names.length ? { items: names.map((n) => resource(n, store.get(n))) } : {}),
      };
      return cleanup ? json(200, body) : answer(json(200, body));
    }
    return json(400, { error: { code: 400, message: "unexpected request" } });
  }
  return { fetchImpl, store, calls, history, startCleanup: () => (cleanup = true) };
}
