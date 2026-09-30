import { EventEmitter } from "node:events";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ADC, OWNER_TOKEN } from "./storage-rules-runner-support.mjs";
import { canonicalDigest } from "./storage-rules-release/release.mjs";

// A scratch code tree, and a fake `https.request` with a small Firebase Rules world: one bucket release that points at a ruleset, deleted and
// published the way the API does, and the identity and token routes.
export const SOURCE_COMMIT = "a".repeat(40);
export const PIN_KEYS = ["packetSha256", "sourceCommit", "runnerSha256", "manifestSha256", "fixtureSchemaSha256"];
export const OWNER_EMAIL = "owner@example.test";
export const OWNER_SUBJECT = "107364905517293846281";
export const ownerDigest = createHash("sha256").update(OWNER_EMAIL).digest("hex");
export const BUCKET = "fixture-query.firebasestorage.app";
export const RULESET = "projects/fireemu-oracle-query/rulesets/22b746af-1111-4222-8333-444455556666";
export const OTHER_RULESET = "projects/fireemu-oracle-query/rulesets/99999999-1111-4222-8333-444455556666";
export const RELEASE_NAME = `projects/fireemu-oracle-query/releases/firebase.storage/${BUCKET}`;
export const RULESET_SOURCE = { files: [{ name: "storage.rules", content: "rules_version = '2';\nservice firebase.storage { match /b/{bucket}/o { match /{allPaths=**} { allow read, write: if false; } } }\n", fingerprint: "abc" }] };
export const SOURCE_SHA = canonicalDigest(RULESET_SOURCE);
export const CODE_FILES = [
  "conformance/src/storage-rules/other.mjs", "conformance/src/storage-rules/nested/deep.mjs",
  "conformance/src/storage-rules-release/release.mjs", "conformance/src/storage-rules-release/targets.mjs", "conformance/src/storage-rules-release/run.mjs", "conformance/src/storage-rules-release/nested/extra.mjs",
];

export function scratchCode() {
  const root = mkdtempSync("/private/tmp/storage-rules-release-code-");
  for (const file of CODE_FILES) {
    mkdirSync(join(root, file, ".."), { recursive: true });
    writeFileSync(join(root, file), `export const name = ${JSON.stringify(file)};\n`);
  }
  return root;
}

const clone = (value) => structuredClone(value);
export const releaseBody = (rulesetName = RULESET, times = { createTime: "2026-09-25T10:30:00.123456Z", updateTime: "2026-09-25T10:30:01.654321Z" }) => ({ name: RELEASE_NAME, rulesetName, ...times });
const ROUTE = /^\/v1\/projects\/fireemu-oracle-query\/releases\/firebase\.storage(?:\/(.+))?$/;

/** The releases the fake production holds. `hook` lets a test replace or observe any answer; a hook may throw to simulate a lost connection. */
export function createReleaseWorld({ release = releaseBody(), bucketless = null, ruleset = { name: RULESET, createTime: "2026-09-25T10:29:00.111111Z", source: RULESET_SOURCE }, extraRulesets = {} } = {}) {
  const world = { release: release === null ? null : clone(release), bucketless: bucketless === null ? null : clone(bucketless), ruleset: clone(ruleset), rulesets: { [ruleset.name]: null, ...extraRulesets }, log: [], deletes: 0, posts: [], hook: {}, clock: 0 };
  const json = (body, status = 200) => ({ status, rawHeaders: ["Content-Type", "application/json; charset=UTF-8"], bytes: Buffer.from(JSON.stringify(body)) });
  const notFound = () => json({ error: { code: 404, message: "Requested entity was not found.", status: "NOT_FOUND" } }, 404);
  world.json = json;
  world.answer = (spec) => {
    const url = new URL(spec.url);
    world.log.push(`${spec.method} ${url.host}${url.pathname}`);
    if (world.hook.any) { const replaced = world.hook.any(world, spec); if (replaced !== undefined) return replaced; }
    if (url.host === "oauth2.googleapis.com" && url.pathname === "/token") return json({ access_token: OWNER_TOKEN, token_type: "Bearer", expires_in: 3600 });
    if (url.host === "www.googleapis.com" && url.pathname === "/oauth2/v2/userinfo") return json(world.hook.identity ?? { id: OWNER_SUBJECT, email: OWNER_EMAIL, verified_email: true });
    if (url.host !== "firebaserules.googleapis.com") throw new Error(`unexpected host ${url.host}`);
    if (spec.method === "GET" && url.pathname === `/v1/${world.ruleset.name}`) {
      if (world.hook.ruleset) { const replaced = world.hook.ruleset(world); if (replaced !== undefined) return replaced; }
      return json(world.ruleset);
    }
    const match = ROUTE.exec(url.pathname);
    if (match && spec.method === "GET") {
      const bucketRoute = match[1] !== undefined;
      if (bucketRoute && match[1] !== BUCKET) throw new Error(`unexpected bucket ${match[1]}`);
      const current = bucketRoute ? world.release : world.bucketless;
      if (world.hook.read) { const replaced = world.hook.read(world, bucketRoute ? "bucket" : "bucketless", current); if (replaced !== undefined) return replaced; }
      return current === null ? notFound() : json(current);
    }
    if (match && spec.method === "DELETE" && match[1] === BUCKET) {
      world.deletes++;
      if (world.hook.delete) { const replaced = world.hook.delete(world, world.deletes); if (replaced !== undefined) return replaced; }
      if (world.release === null) return notFound();
      world.release = null;
      return json({});
    }
    if (url.pathname === "/v1/projects/fireemu-oracle-query/releases" && spec.method === "POST") {
      const body = JSON.parse(spec.body.toString("utf8"));
      world.posts.push(body);
      if (world.hook.post) { const replaced = world.hook.post(world, body, world.posts.length); if (replaced !== undefined) return replaced; }
      if (world.release !== null) return json({ error: { code: 409, message: "exists", status: "ALREADY_EXISTS" } }, 409);
      world.clock++;
      world.release = { name: body.name, rulesetName: body.rulesetName, createTime: `2026-09-29T14:00:0${world.clock}.000000Z`, updateTime: `2026-09-29T14:00:0${world.clock}.000000Z` };
      return json(world.release);
    }
    throw new Error(`unexpected route ${spec.method} ${spec.url}`);
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

export const preLocal = (adcPath) => ({ schemaVersion: 1, adcPath, ownerEmailSha256: ownerDigest, bucket: BUCKET, expectedRulesetName: RULESET });
export const postLocal = (adcPath, savedPath) => ({ schemaVersion: 1, adcPath, ownerEmailSha256: ownerDigest, savedPath });
export const cleanup = (path) => rmSync(path, { recursive: true, force: true });
export { ADC, OWNER_TOKEN };
