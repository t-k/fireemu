// A stateful fake of production for the probe-v4 tests: an object store that refuses what the probe
// asks it to refuse, in the shapes production answers with, and, when `acceptRefused` is set, one
// that wrongly accepts every write it should have refused. Not a test file: the tests import it.

export const BUCKET = "fireemu-oracle-query.firebasestorage.app";

export const json = (status, body, headers = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=UTF-8", ...headers },
  });
const fail = (code, message) => json(code, { error: { code, message, errors: [] } });

/**
 * Options:
 * - `acceptRefused`: every write that should be refused is accepted and applied (a create replaces
 *   the object, a delete deletes, a wrong-offset chunk is taken);
 * - `odd`: every answer before the Firebase session starts is a plain-text 200 that says nothing (the
 *   effects still happen), and the session carries no URL;
 * - `failAt`: the nth request throws like a lost connection;
 * - `noGeneration`: after the recording, a metadata read gives no generation;
 * - `deleteFails`: a delete of this name answers 500;
 * - `strays`, `strayPrefix`: objects that exist under the prefix before the run.
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
    const match = query.get("ifGenerationMatch");
    if (match !== null && match !== o.generation) return fail(412, "Precondition Failed");
    const metaMatch = query.get("ifMetagenerationMatch");
    if (metaMatch !== null && metaMatch !== String(o.metageneration))
      return fail(412, "Precondition Failed");
    const notMatch = query.get("ifGenerationNotMatch");
    if (notMatch !== null && notMatch === o.generation) return fail(412, "Precondition Failed");
    const metaNotMatch = query.get("ifMetagenerationNotMatch");
    if (metaNotMatch !== null && metaNotMatch === String(o.metageneration))
      return fail(412, "Precondition Failed");
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

    // ---- GCS upload (a create) ----
    if (path.startsWith("/upload/storage/v1/b/") && method === "POST") {
      const name = q.get("name");
      const o = store.get(name);
      if (o) {
        const no = refused(q, o);
        if (no) return answer(no);
      } else if (q.get("ifGenerationMatch") !== null && q.get("ifGenerationMatch") !== "0")
        return answer(fail(412, "Precondition Failed"));
      return answer(json(200, resource(name, put(name, size))));
    }
    // ---- Firebase resumable ----
    if (path === `/v0/b/${BUCKET}/o` && method === "POST") {
      if (command === "start") {
        const id = `f${sessions.size + 1}`;
        sessions.set(id, { name: q.get("name"), received: 0, open: true });
        const response = answer(
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
        // The last request whose answer the recording judges nothing by: from here on, honest answers.
        cleanup = true;
        return response;
      }
      const session = sessions.get(q.get("upload_id"));
      if (!session) return fail(404, "Not Found");
      if (command === "cancel") {
        session.open = false;
        return new Response(null, {
          status: 200,
          headers: { "x-goog-upload-status": "cancelled" },
        });
      }
      if (command === "query")
        return new Response(null, {
          status: 200,
          headers: {
            "x-goog-upload-status": session.open ? "active" : "cancelled",
            ...(session.open ? { "x-goog-upload-size-received": String(session.received) } : {}),
          },
        });
      const offset = Number(new Headers(init.headers).get("x-goog-upload-offset") ?? 0);
      if (offset !== session.received && !options.acceptRefused)
        return new Response("Invalid offset", {
          status: 400,
          headers: { "content-type": "text/plain" },
        });
      session.received += size;
      return new Response(null, { status: 200, headers: { "x-goog-upload-status": "active" } });
    }
    // ---- GCS objects ----
    if (path.startsWith(`/storage/v1/b/${BUCKET}/o/`)) {
      const name = decodeURIComponent(path.split("/o/").slice(1).join("/o/"));
      const o = store.get(name);
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
    // ---- GCS list of the prefix ----
    if (path === `/storage/v1/b/${BUCKET}/o` && method === "GET") {
      const names = [...store.keys()].filter((n) => n.startsWith(q.get("prefix"))).toSorted();
      return json(200, {
        kind: "storage#objects",
        ...(names.length ? { items: names.map((n) => resource(n, store.get(n))) } : {}),
      });
    }
    return json(400, { error: { code: 400, message: "unexpected request" } });
  }
  return { fetchImpl, store, calls, history };
}
