import { EventEmitter } from "node:events";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ADC, OWNER_TOKEN } from "./storage-rules-runner-support.mjs";
import { compileSources, PROBE_DOCUMENT, PROBE_OBJECT } from "./storage-rules-probe/probe.mjs";

// A scratch code tree, and a fake `https.request` that answers the probe's routes. The answers are the shapes production is believed to return; a test
// can replace any of them, and the probe must record whatever comes back.
export const SOURCE_COMMIT = "a".repeat(40);
export const PIN_KEYS = ["packetSha256", "sourceCommit", "runnerSha256", "manifestSha256", "fixtureSchemaSha256"];
export const OWNER_EMAIL = "owner@example.test";
export const OWNER_SUBJECT = "107364905517293846281";
export const ownerDigest = createHash("sha256").update(OWNER_EMAIL).digest("hex");
export const BUCKET = "fixture-query.firebasestorage.app";
export const CODE_FILES = [
  "conformance/src/storage-rules/other.mjs", "conformance/src/storage-rules/nested/deep.mjs",
  "conformance/src/storage-rules-probe/probe.mjs", "conformance/src/storage-rules-probe/targets.mjs", "conformance/src/storage-rules-probe/run.mjs", "conformance/src/storage-rules-probe/nested/extra.mjs",
];

export function scratchCode() {
  const root = mkdtempSync("/private/tmp/storage-rules-probe-code-");
  for (const file of CODE_FILES) {
    mkdirSync(join(root, file, ".."), { recursive: true });
    writeFileSync(join(root, file), `export const name = ${JSON.stringify(file)};\n`);
  }
  return root;
}

export const RULESET_LIST = { rulesets: [
  { name: "projects/fireemu-oracle-query/rulesets/22b746af-a48a-458d-ab5c-7853473bc8c8", createTime: "2026-09-25T11:08:54.358767Z", metadata: { services: ["firebase.storage"] } },
  { name: "projects/fireemu-oracle-query/rulesets/d0abf7c6-b0b6-4163-8488-7c8a48ac5dd1", createTime: "2026-09-23T23:02:05.839536Z", metadata: { services: ["cloud.firestore"] } },
] };
const gcsNotFound = { error: { code: 404, message: `No such object: ${BUCKET}/${PROBE_OBJECT}`, errors: [{ message: `No such object: ${BUCKET}/${PROBE_OBJECT}`, domain: "global", reason: "notFound" }] } };
const invalidTest = { error: { code: 400, message: "Invalid argument", status: "INVALID_ARGUMENT" } };
const firestoreNotFound = { error: { code: 404, message: `Document "projects/fireemu-oracle-query/databases/(default)/documents/${PROBE_DOCUMENT}" not found.`, status: "NOT_FOUND" } };

/** The probe's world: `hook.answer(spec, key)` may replace any answer, `hook.any(spec)` sees every request first, and a hook may throw to lose the connection. */
export function createProbeWorld() {
  const world = { log: [], hook: {}, calls: {} };
  const json = (body, status = 200) => ({ status, rawHeaders: ["Content-Type", "application/json; charset=UTF-8"], bytes: Buffer.from(JSON.stringify(body)) });
  world.json = json;
  world.answer = (spec) => {
    const url = new URL(spec.url);
    world.log.push(`${spec.method} ${url.host}${url.pathname}${url.search}`);
    if (world.hook.any) { const replaced = world.hook.any(spec); if (replaced !== undefined) return replaced; }
    const key = (() => {
      if (url.host === "oauth2.googleapis.com" && url.pathname === "/token") return "token";
      if (url.host === "www.googleapis.com" && url.pathname === "/oauth2/v2/userinfo") return "identity";
      if (url.host === "firebaserules.googleapis.com" && url.pathname.endsWith("/rulesets")) return "list";
      if (url.host === "storage.googleapis.com") return url.search === "?alt=media" ? "media" : "metadata";
      if (url.host === "firebaserules.googleapis.com" && url.pathname.endsWith(":test")) return JSON.parse(spec.body.toString("utf8")).source.files[0].content === compileSources(BUCKET).invalid ? "testInvalid" : "testValid";
      if (url.host === "firestore.googleapis.com") return "document";
      throw new Error(`unexpected route ${spec.method} ${spec.url}`);
    })();
    world.calls[key] = (world.calls[key] ?? 0) + 1;
    if (world.hook.answer) { const replaced = world.hook.answer(spec, key); if (replaced !== undefined) return replaced; }
    return ({
      token: () => json({ access_token: OWNER_TOKEN, token_type: "Bearer", expires_in: 3600 }),
      identity: () => json({ id: OWNER_SUBJECT, email: OWNER_EMAIL, verified_email: true }),
      list: () => json(RULESET_LIST),
      metadata: () => json(gcsNotFound, 404),
      media: () => ({ status: 404, rawHeaders: ["Content-Type", "text/plain; charset=utf-8"], bytes: Buffer.from(`No such object: ${BUCKET}/${PROBE_OBJECT}`) }),
      testValid: () => json({}),
      testInvalid: () => json(invalidTest, 400),
      document: () => json(firestoreNotFound, 404),
    })[key]();
  };
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

export const probeLocal = (adcPath) => ({ schemaVersion: 1, adcPath, ownerEmailSha256: ownerDigest, bucket: BUCKET });
export const cleanup = (path) => rmSync(path, { recursive: true, force: true });
export { ADC, OWNER_TOKEN };
