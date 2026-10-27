// A fake Cloud Storage JSON API world for the Gen2 source upload tests: one bucket, objects with
// generations, paged lists, and per-request answer overrides. It follows the recorded shapes:
// a list answers `{ items: [{ name, generation }], nextPageToken }`, a metadata GET answers
// `{ bucket, name, generation }`, a conditional DELETE answers 204 or 412, a missing object or
// bucket answers a 404 error body.

export const FAKE_PROJECT_NUMBER = "123456789012";
export const FAKE_REGION = "us-central1";
export const FAKE_BUCKET = `gcf-v2-uploads-${FAKE_PROJECT_NUMBER}.${FAKE_REGION}.cloudfunctions.appspot.com`;
export const SECRET_MARKER = "SECRET-MARKER-9f3a";

export function createFakeGcs({ bucket = FAKE_BUCKET, bucketExists = true } = {}) {
  const objects = new Map();
  const requests = [];
  const overrides = [];
  let generation = 1_700_000_000_000_000;
  let exists = bucketExists;
  const world = {
    requests,
    objects,
    bucket,
    put(name) {
      generation += 1;
      objects.set(name, { generation: String(generation), size: 35_872 });
      return String(generation);
    },
    remove(name) {
      objects.delete(name);
    },
    setBucketExists(value) {
      exists = value;
    },
    /** The next request matching `match` (method and URL substring) answers `answer` instead. */
    override(match, answer, { times = 1, effect } = {}) {
      overrides.push({ match, answer, times, effect });
    },
    count(method) {
      return requests.filter((request) => request.method === method).length;
    },
    async send(method, url) {
      requests.push({ method, url });
      const hit = overrides.find(
        (entry) =>
          entry.times > 0 && entry.match.method === method && url.includes(entry.match.url),
      );
      if (hit) {
        hit.times -= 1;
        hit.effect?.();
        if (hit.answer instanceof Error) throw hit.answer;
        return hit.answer;
      }
      const parsed = new URL(url);
      const prefix = `/storage/v1/b/${bucket}/o`;
      if (parsed.origin !== "https://storage.googleapis.com") {
        return { status: 400, bodyReadable: true, value: { error: "host" }, bytes: 20 };
      }
      if (!exists || !parsed.pathname.startsWith(`/storage/v1/b/${bucket}`)) {
        return { status: 404, bodyReadable: true, value: { error: { code: 404 } }, bytes: 40 };
      }
      if (parsed.pathname === prefix && method === "GET") {
        const names = [...objects.keys()].toSorted();
        const max = Number(parsed.searchParams.get("maxResults") ?? 1000);
        const start = Number(parsed.searchParams.get("pageToken") ?? 0);
        const page = names.slice(start, start + max);
        const next = start + max < names.length ? { nextPageToken: String(start + max) } : {};
        return {
          status: 200,
          bodyReadable: true,
          value: {
            items: page.map((name) => ({ name, generation: objects.get(name).generation })),
            ...next,
          },
          bytes: 200 + page.length * 80,
        };
      }
      if (parsed.pathname.startsWith(`${prefix}/`)) {
        const name = decodeURIComponent(parsed.pathname.slice(prefix.length + 1));
        const found = objects.get(name);
        if (!found) {
          return { status: 404, bodyReadable: true, value: { error: { code: 404 } }, bytes: 40 };
        }
        if (method === "GET") {
          return {
            status: 200,
            bodyReadable: true,
            value: { bucket, name, generation: found.generation },
            bytes: 120,
          };
        }
        if (method === "DELETE") {
          const condition = parsed.searchParams.get("ifGenerationMatch");
          if (condition !== found.generation) {
            return { status: 412, bodyReadable: true, value: { error: { code: 412 } }, bytes: 40 };
          }
          objects.delete(name);
          return { status: 204, bodyReadable: true, value: {}, bytes: 0 };
        }
      }
      return { status: 400, bodyReadable: true, value: { error: "unhandled" }, bytes: 20 };
    },
  };
  return world;
}

export const ok204 = { status: 204, bodyReadable: true, value: {}, bytes: 0 };
export const answer = (status, value = {}) => ({
  status,
  bodyReadable: true,
  value,
  bytes: 40,
});
