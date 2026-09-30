import { EventEmitter } from "node:events";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ADC, OWNER_TOKEN } from "./storage-rules-runner-support.mjs";
import { ENTRY_RULESETS } from "./storage-rules/entry-rulesets.mjs";

// A scratch code tree, an expected state of the size the stage 2e approval names (7 objects, 3 accounts, 4 rulesets) and a fake production that holds it: objects with
// generations, accounts, the run's rulesets next to the two kept ones, no release. A deletion changes the world the way the API does.
export const SOURCE_COMMIT = "a".repeat(40);
export const PIN_KEYS = ["packetSha256", "sourceCommit", "runnerSha256", "manifestSha256", "fixtureSchemaSha256"];
export const OWNER_EMAIL = "owner@example.test";
export const OWNER_SUBJECT = "107364905517293846281";
export const ownerDigest = createHash("sha256").update(OWNER_EMAIL).digest("hex");
export const BUCKET = "fixture-query.firebasestorage.app";
export const RUN = "stage3-test";
export const PREFIX = `STORAGE-RULES/${RUN}/`;
export const CODE_FILES = [
  "conformance/src/storage-rules/other.mjs", "conformance/src/storage-rules/nested/deep.mjs",
  "conformance/src/storage-rules-restore/state.mjs", "conformance/src/storage-rules-restore/plan.mjs", "conformance/src/storage-rules-restore/targets.mjs", "conformance/src/storage-rules-restore/run.mjs", "conformance/src/storage-rules-restore/nested/extra.mjs",
];
export const STATE = {
  schemaVersion: 1, runId: RUN, runPrefix: PREFIX, bucket: BUCKET,
  objects: ["list-v1-read-get-media-present/settle-allow.bin", "method-get-get-media-present/settle-allow.bin", "method-read-delete-present/object.bin", "no-release/object.bin", "release-switch/new.bin", "release-switch/old.bin", "settle-control/deny.bin"].map((name, index) => ({ name: `${PREFIX}${name}`, generation: `17907274283923${index}5` })),
  accounts: ["revoked-token", "user-a", "user-b"].map((name) => `storage-rules-${RUN}-${name}`),
  rulesets: ["05a32c2b-3455-428e-8e62-a4b9b8ca12b3", "3ab2198e-33ba-48d2-8029-803527d6a02e", "8fd1cff8-c57a-4dbf-a3aa-2bf2873901e3", "cf1570f9-edd5-4c0d-8e74-431f356ed9b4"].map((id) => `projects/fireemu-oracle-query/rulesets/${id}`),
};

export function scratchCode() {
  const root = mkdtempSync("/private/tmp/storage-rules-restore-code-");
  for (const file of CODE_FILES) {
    mkdirSync(join(root, file, ".."), { recursive: true });
    writeFileSync(join(root, file), `export const name = ${JSON.stringify(file)};\n`);
  }
  return root;
}

const clone = (value) => structuredClone(value);
const gcsNotFound = (name) => ({ error: { code: 404, message: `No such object: ${BUCKET}/${name}`, errors: [{ message: `No such object: ${BUCKET}/${name}`, domain: "global", reason: "notFound" }] } });
const rpcNotFound = { error: { code: 404, message: "Requested entity was not found.", status: "NOT_FOUND" } };

/** The world: `hook.any(spec)` sees every request first and `hook.answer(spec, key, world)` may replace the answer; either may throw to lose the connection. */
export function createRestoreWorld(state = STATE) {
  const world = { objects: new Map(state.objects.map((object) => [object.name, object.generation])), accounts: new Set(state.accounts), rulesets: new Set(state.rulesets), release: null, log: [], hook: {}, calls: {}, deletes: [] };
  const json = (body, status = 200) => ({ status, rawHeaders: ["Content-Type", "application/json; charset=UTF-8"], bytes: Buffer.from(JSON.stringify(body)) });
  world.json = json;
  world.answer = (spec) => {
    const url = new URL(spec.url);
    const key = `${spec.method} ${url.host}${url.pathname}${url.search}`;
    world.log.push(key);
    world.calls[key] = (world.calls[key] ?? 0) + 1;
    if (world.hook.any) { const replaced = world.hook.any(spec); if (replaced !== undefined) return replaced; }
    if (world.hook.answer) { const replaced = world.hook.answer(spec, key, world); if (replaced !== undefined) return replaced; }
    if (url.host === "oauth2.googleapis.com" && url.pathname === "/token") return json({ access_token: OWNER_TOKEN, token_type: "Bearer", expires_in: 3600 });
    if (url.host === "www.googleapis.com" && url.pathname === "/oauth2/v2/userinfo") return json({ id: OWNER_SUBJECT, email: OWNER_EMAIL, verified_email: true });
    if (url.host === "firebaserules.googleapis.com") {
      if (url.pathname.includes("/releases/")) return json(rpcNotFound, 404);
      if (spec.method === "GET" && url.pathname.endsWith("/rulesets")) return json({ rulesets: [...ENTRY_RULESETS.map((entry, index) => ({ name: entry.name, createTime: ["2026-09-25T11:08:54.358767Z", "2026-09-23T23:02:05.839536Z"][index], metadata: { services: [...entry.services] } })), ...[...world.rulesets].map((name) => ({ name, createTime: "2026-09-30T00:23:49.178351Z", metadata: { services: ["firebase.storage"] } }))] });
      const match = /^\/v1\/(projects\/fireemu-oracle-query\/rulesets\/[^/]+)$/.exec(url.pathname);
      if (spec.method === "DELETE" && match) { world.deletes.push(match[1]); if (!world.rulesets.has(match[1])) return json(rpcNotFound, 404); world.rulesets.delete(match[1]); return json({}); }
    }
    if (url.host === "storage.googleapis.com") {
      const match = /^\/storage\/v1\/b\/([^/]+)\/o\/(.+)$/.exec(url.pathname);
      if (match) {
        const name = decodeURIComponent(match[2]);
        if (spec.method === "GET") return world.objects.has(name) ? json({ kind: "storage#object", bucket: BUCKET, name, generation: world.objects.get(name), metageneration: "2", size: "4" }) : json(gcsNotFound(name), 404);
        if (spec.method === "DELETE") {
          world.deletes.push(name);
          if (!world.objects.has(name)) return json(gcsNotFound(name), 404);
          if (url.searchParams.get("ifGenerationMatch") !== world.objects.get(name)) return json({ error: { code: 412, message: "Precondition Failed" } }, 412);
          world.objects.delete(name);
          return { status: 204, rawHeaders: [], bytes: Buffer.alloc(0) };
        }
      }
      if (spec.method === "GET" && url.pathname === `/storage/v1/b/${BUCKET}/o`) return json(world.objects.size === 0 ? { kind: "storage#objects" } : { kind: "storage#objects", items: [{ kind: "storage#object", name: [...world.objects.keys()][0] }] });
    }
    if (url.host === "identitytoolkit.googleapis.com") {
      const body = JSON.parse(spec.body.toString("utf8"));
      if (url.pathname.endsWith(":lookup")) { const users = body.localId.filter((uid) => world.accounts.has(uid)).map((localId) => ({ localId, email: `${localId}@example.test` })); return json(users.length === 0 ? { kind: "identitytoolkit#GetAccountInfoResponse" } : { kind: "identitytoolkit#GetAccountInfoResponse", users }); }
      if (url.pathname.endsWith(":delete")) { world.deletes.push(body.localId); if (!world.accounts.has(body.localId)) return json({ error: { code: 400, message: "USER_NOT_FOUND" } }, 400); world.accounts.delete(body.localId); return json({ kind: "identitytoolkit#DeleteAccountResponse" }); }
    }
    throw new Error(`unexpected route ${key}`);
  };
  world.clean = () => world.objects.size === 0 && world.accounts.size === 0 && [...world.rulesets].length === 0;
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

export const restoreLocal = (adcPath, statePath) => ({ schemaVersion: 1, adcPath, ownerEmailSha256: ownerDigest, statePath });
export const cleanup = (path) => rmSync(path, { recursive: true, force: true });
export { ADC, OWNER_TOKEN };
