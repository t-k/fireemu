// A rehearsal helper: a `fetch` that stands in for the four real hosts the lean wire sends to, so
// a local run can go through `lean-wire.mjs` itself against a local fireemu. It sends nothing
// anywhere else, and it is used only by `local-aggregate.mjs`.

const REAL = Object.freeze({
  firebase: "https://firebasestorage.googleapis.com",
  gcs: "https://storage.googleapis.com",
  identity: "https://identitytoolkit.googleapis.com",
  token: "https://securetoken.googleapis.com",
});

export function createLocalFetchForLeanWire({ local, ownerToken, fetchImpl }) {
  const target = (url) => {
    const parsed = new URL(url);
    const rest = `${parsed.pathname}${parsed.search}`;
    if (parsed.origin === REAL.firebase || parsed.origin === REAL.gcs)
      return `${local.storage}${rest}`;
    if (parsed.origin === REAL.identity)
      return `${local.auth}/identitytoolkit.googleapis.com${rest}`;
    if (parsed.origin === REAL.token) return `${local.auth}/securetoken.googleapis.com${rest}`;
    throw new Error("rehearsal fetch: not one of the four real hosts");
  };
  return async function localFetch(url, init = {}) {
    const headers = new Headers(init.headers ?? {});
    if (headers.get("authorization") === `Bearer ${ownerToken}`)
      headers.set("authorization", "Bearer owner");
    const response = await fetchImpl(target(url), { ...init, headers });
    const out = new Headers(response.headers);
    for (const name of ["location", "x-goog-upload-url"]) {
      const value = out.get(name);
      if (value?.startsWith(local.storage)) {
        const rest = value.slice(local.storage.length);
        out.set(name, `${rest.startsWith("/v0/") ? REAL.firebase : REAL.gcs}${rest}`);
      }
    }
    const bytes = [204, 205, 304].includes(response.status) ? null : await response.arrayBuffer();
    return new Response(bytes, {
      status: response.status,
      statusText: response.statusText,
      headers: out,
    });
  };
}
