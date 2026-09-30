import { EventEmitter } from "node:events";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ADC, OWNER_TOKEN } from "./storage-rules-runner-support.mjs";
import { ENTRY_RULESETS } from "./storage-rules/entry-rulesets.mjs";

// A scratch code tree and a fake production for the stage 2f probe: the two kept rulesets, no object under the probe's prefix, no probe document. A creation and a deletion change the world the way the APIs do.
export const SOURCE_COMMIT = "a".repeat(40);
export const PIN_KEYS = ["packetSha256", "sourceCommit", "runnerSha256", "manifestSha256", "fixtureSchemaSha256"];
export const OWNER_EMAIL = "owner@example.test";
export const OWNER_SUBJECT = "107364905517293846281";
export const ownerDigest = createHash("sha256").update(OWNER_EMAIL).digest("hex");
export const BUCKET = "fixture-query.firebasestorage.app";
export const CODE_FILES = [
  "conformance/src/storage-rules/other.mjs", "conformance/src/storage-rules/nested/deep.mjs",
  "conformance/src/storage-rules-shape/plan.mjs", "conformance/src/storage-rules-shape/judge.mjs", "conformance/src/storage-rules-shape/targets.mjs", "conformance/src/storage-rules-shape/run.mjs", "conformance/src/storage-rules-shape/nested/extra.mjs",
];
export const OBJECT = "STORAGE-RULES/probe-2f/object.bin";
export const DOCUMENT = "projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES/probe-2f-doc";
export const RULESET_ID = "3f2a9c1e-7b64-4d0a-9e51-0c8a6f2b7d14";
export const RULESET = `projects/fireemu-oracle-query/rulesets/${RULESET_ID}`;

export function scratchCode() {
  const root = mkdtempSync("/private/tmp/storage-rules-shape-code-");
  for (const file of CODE_FILES) {
    mkdirSync(join(root, file, ".."), { recursive: true });
    writeFileSync(join(root, file), `export const name = ${JSON.stringify(file)};\n`);
  }
  return root;
}

const KEPT_TIMES = ["2026-09-25T11:08:54.358767Z", "2026-09-23T23:02:05.839536Z"];
const rpcNotFound = { error: { code: 404, message: "Requested entity was not found.", status: "NOT_FOUND" } };
const docNotFound = { error: { code: 404, message: `Document "${DOCUMENT}" not found.`, status: "NOT_FOUND" } };
const gcsNotFound = (name) => ({ error: { code: 404, message: `No such object: ${BUCKET}/${name}`, errors: [{ message: `No such object: ${BUCKET}/${name}`, domain: "global", reason: "notFound" }] } });

/** The world: `hook.any(spec)` sees every request first and `hook.answer(spec, key, world)` may replace the answer; either may throw to lose the connection. */
export function createShapeWorld() {
  const world = { rulesets: new Map(), object: null, document: null, log: [], hook: {}, calls: {}, sent: [] };
  const json = (body, status = 200) => ({ status, rawHeaders: ["Content-Type", "application/json; charset=UTF-8"], bytes: Buffer.from(JSON.stringify(body)) });
  world.json = json;
  world.answer = (spec) => {
    const url = new URL(spec.url);
    const key = `${spec.method} ${url.host}${url.pathname}${url.search}`;
    world.log.push(key);
    world.calls[key] = (world.calls[key] ?? 0) + 1;
    if (spec.method !== "GET") world.sent.push({ method: spec.method, key });
    if (world.hook.any) { const replaced = world.hook.any(spec); if (replaced !== undefined) return replaced; }
    if (world.hook.answer) { const replaced = world.hook.answer(spec, key, world); if (replaced !== undefined) return replaced; }
    if (url.host === "oauth2.googleapis.com" && url.pathname === "/token") return json({ access_token: OWNER_TOKEN, token_type: "Bearer", expires_in: 3600 });
    if (url.host === "www.googleapis.com" && url.pathname === "/oauth2/v2/userinfo") return json({ id: OWNER_SUBJECT, email: OWNER_EMAIL, verified_email: true });
    if (url.host === "firebaserules.googleapis.com") {
      if (spec.method === "GET" && url.pathname === "/v1/projects/fireemu-oracle-query/rulesets") return json({ rulesets: [...ENTRY_RULESETS.map((entry, index) => ({ name: entry.name, createTime: KEPT_TIMES[index], metadata: { services: [...entry.services] } })), ...[...world.rulesets.entries()].map(([name, createTime]) => ({ name, createTime, metadata: { services: ["firebase.storage"] } }))] });
      if (spec.method === "POST" && url.pathname === "/v1/projects/fireemu-oracle-query/rulesets") { world.rulesets.set(RULESET, "2026-09-30T02:30:00.123456Z"); return json({ name: RULESET, createTime: "2026-09-30T02:30:00.123456Z" }); }
      const match = /^\/v1\/(projects\/fireemu-oracle-query\/rulesets\/[^/]+)$/.exec(url.pathname);
      if (match && spec.method === "GET") return world.rulesets.has(match[1]) ? json({ name: match[1], createTime: world.rulesets.get(match[1]), source: { files: [] } }) : json(rpcNotFound, 404);
      if (match && spec.method === "DELETE") { if (!world.rulesets.has(match[1])) return json(rpcNotFound, 404); world.rulesets.delete(match[1]); return json({}); }
    }
    if (url.host === "storage.googleapis.com") {
      if (spec.method === "POST" && url.pathname === `/upload/storage/v1/b/${BUCKET}/o`) { world.object = "1790727977683752"; return json({ kind: "storage#object", bucket: BUCKET, name: url.searchParams.get("name"), generation: world.object, metageneration: "1", size: "8" }); }
      if (spec.method === "GET" && url.pathname === `/storage/v1/b/${BUCKET}/o`) return json(world.object === null ? { kind: "storage#objects" } : { kind: "storage#objects", items: [{ kind: "storage#object", name: OBJECT, generation: world.object }] });
      if (spec.method === "DELETE" && url.pathname === `/storage/v1/b/${BUCKET}/o/${encodeURIComponent(OBJECT)}`) { if (world.object === null) return json(gcsNotFound(OBJECT), 404); world.object = null; return { status: 204, rawHeaders: [], bytes: Buffer.alloc(0) }; }
    }
    if (url.host === "firestore.googleapis.com") {
      if (spec.method === "POST" && url.pathname === "/v1/projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES") { world.document = "2026-09-30T02:30:01.654321Z"; return json({ name: DOCUMENT, fields: { probe: { stringValue: "2f" } }, createTime: world.document, updateTime: world.document }); }
      if (url.pathname === `/v1/${DOCUMENT}`) {
        if (spec.method === "GET") return world.document === null ? json(docNotFound, 404) : json({ name: DOCUMENT, fields: {}, createTime: world.document, updateTime: world.document });
        if (spec.method === "DELETE") { world.document = null; return json({}); }
      }
    }
    throw new Error(`unexpected route ${key}`);
  };
  world.clean = () => world.rulesets.size === 0 && world.object === null && world.document === null;
  return world;
}

/** A fake `https.request` that answers from `answer` and records what it saw. `answer` may throw to simulate a lost connection. */
export function fakeRequestImpl(answer, log) {
  return (url, options, callback) => {
    const request = new EventEmitter();
    const response = new EventEmitter();
    Object.assign(response, { complete: false, destroyed: false, destroy() { response.destroyed = true; } });
    Object.assign(request, { destroyed: false, destroy() { request.destroyed = true; } });
    request.write = () => {};
    request.end = (body) => {
      const entry = { url: String(url), method: options.method, headers: options.headers, body: body === undefined ? null : Buffer.from(body) };
      log.push(entry);
      queueMicrotask(() => {
        let made;
        try { made = answer({ url: entry.url, method: entry.method, headers: entry.headers, body: entry.body ?? Buffer.alloc(0) }); } catch (error) { request.emit("error", error); return; }
        response.statusCode = made.status;
        response.rawHeaders = made.rawHeaders;
        callback(response);
        response.emit("data", made.bytes);
        response.complete = true;
        response.emit("end");
        response.emit("close");
        request.emit("close");
      });
    };
    return request;
  };
}

export const shapeLocal = (adcPath) => ({ schemaVersion: 1, adcPath, ownerEmailSha256: ownerDigest, bucket: BUCKET });
export const cleanup = (path) => rmSync(path, { recursive: true, force: true });
export { ADC, OWNER_TOKEN };
