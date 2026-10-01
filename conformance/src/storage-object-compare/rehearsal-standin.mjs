// A rehearsal-only preload (`node --import`): when local fireemu answers 501 to the GCS object
// update (`PUT /storage/v1/b/<bucket>/o/<name>`), this answers in its place, in the shape
// production recorded, and marks the answer with `x-compare-standin` so that the comparison counts
// it as LOCAL_UNIMPLEMENTED and never as a match. Every other request, and every PUT fireemu does
// answer, goes through untouched. It sends nothing anywhere but the local fireemu.
//
// The shape is the recorded production answer to an accepted PUT (the key set of the 200 body of
// the first PUT in the fixture), with the guards evaluated against fireemu's current metadata: 304
// for a not-match guard that names the current value, 412 for a match guard that does not hold,
// 400 for a value that is not a signed integer (production answered -1 as a number: 412 for a match
// guard, applied for a not-match guard). The update is applied to fireemu as a PATCH that nulls the
// metadata keys the PUT body does not carry.

import { readFileSync } from "node:fs";
import { join } from "node:path";

const origin = process.env.STANDIN_STORAGE_ORIGIN;
const fixtureDirectory = process.env.STANDIN_FIXTURE;
const real = globalThis.fetch;
const isPut = (url, method) =>
  method === "PUT" && /^\/storage\/v1\/b\/[^/]+\/o\/[^/]+$/.test(new URL(url).pathname);

function recordedKeys() {
  const index = JSON.parse(readFileSync(join(fixtureDirectory, "index.json"), "utf8"));
  for (const entry of index.recipes) {
    const file = JSON.parse(readFileSync(join(fixtureDirectory, entry.file), "utf8"));
    const row = file.exchanges.find(
      (exchange) =>
        exchange.method === "PUT" &&
        exchange.route.startsWith("PUT /storage/v1/") &&
        exchange.status === 200 &&
        exchange.body.type === "json",
    );
    if (row) return Object.keys(row.body.value);
  }
  throw new Error("the fixture has no accepted PUT to take the key set from");
}

const keys = origin && fixtureDirectory ? recordedKeys() : [];
const GUARDS = [
  ["ifGenerationMatch", "generation", false],
  ["ifGenerationNotMatch", "generation", true],
  ["ifMetagenerationMatch", "metageneration", false],
  ["ifMetagenerationNotMatch", "metageneration", true],
];
const marked = (response) => {
  const headers = new Headers(response.headers);
  headers.set("x-compare-standin", "1");
  return new Response(response.body, { status: response.status, headers });
};
const failure = (code, message, reason) =>
  Response.json(
    { error: { code, message, errors: [{ message, domain: "global", reason }] } },
    { status: code },
  );

async function standIn(url, init) {
  const base = new URL(url.pathname, url.origin);
  const current = await real(base.href, { method: "GET", headers: init.headers });
  if (current.status !== 200) return marked(current);
  const object = await current.json();
  for (const [key, field, negated] of GUARDS) {
    if (!url.searchParams.has(key)) continue;
    const value = url.searchParams.get(key);
    // Production reads a guard as a signed long: -1 is a number that matches nothing (a match guard
    // fails with 412, a not-match guard holds), while an empty value, a fraction or text is 400.
    if (!/^-?[0-9]+$/.test(value))
      return marked(failure(400, `Invalid value for ${key}`, "invalid"));
    const equal = BigInt(value) === BigInt(object[field]);
    if (negated ? equal : !equal)
      return marked(
        negated
          ? new Response(null, { status: 304, headers: { "content-type": "application/json" } })
          : failure(
              412,
              "At least one of the pre-conditions you specified did not hold.",
              "conditionNotMet",
            ),
      );
  }
  const body = JSON.parse(Buffer.from(init.body ?? "{}").toString("utf8"));
  const metadata = { ...body.metadata };
  for (const name of Object.keys(object.metadata ?? {}))
    if (!(name in metadata)) metadata[name] = null;
  const headers = {
    ...Object.fromEntries(new Headers(init.headers)),
    "content-type": "application/json",
  };
  const patch = JSON.stringify({
    ...(body.contentType ? { contentType: body.contentType } : {}),
    metadata,
  });
  // fireemu serves the object update on the short spelling in older builds and on both in newer ones.
  let applied = await real(base.href, { method: "PATCH", headers, body: patch });
  if (applied.status === 501)
    applied = await real(new URL(url.pathname.replace(/^\/storage\/v1/, ""), url.origin).href, {
      method: "PATCH",
      headers,
      body: patch,
    });
  if (applied.status !== 200) return marked(applied);
  const updated = await applied.json();
  const name = encodeURIComponent(updated.name);
  const fallback = {
    kind: "storage#object",
    id: `${updated.bucket}/${updated.name}/${updated.generation}`,
    selfLink: `https://www.googleapis.com/storage/v1/b/${updated.bucket}/o/${name}`,
    mediaLink: `https://storage.googleapis.com/download/storage/v1/b/${updated.bucket}/o/${name}?generation=${updated.generation}&alt=media`,
    storageClass: "STANDARD",
    etag: `standin-${updated.metageneration}`,
    timeFinalized: updated.timeCreated,
  };
  const out = {};
  for (const key of keys) {
    if (key === "metadata") {
      if (updated.metadata && Object.keys(updated.metadata).length > 0)
        out.metadata = updated.metadata;
    } else if (updated[key] !== undefined) out[key] = updated[key];
    else if (fallback[key] !== undefined) out[key] = fallback[key];
  }
  return marked(
    Response.json(out, { headers: { "content-type": "application/json; charset=UTF-8" } }),
  );
}

if (origin && fixtureDirectory)
  globalThis.fetch = async function compareFetch(input, init = {}) {
    const url = new URL(typeof input === "string" ? input : (input.url ?? String(input)));
    const method = (init.method ?? "GET").toUpperCase();
    if (url.origin !== origin || !isPut(url.href, method)) return real(input, init);
    const answered = await real(input, init);
    // A PUT fireemu serves is not replaced; the stand-in only fills a 501.
    return answered.status === 501 ? standIn(url, init) : answered;
  };
