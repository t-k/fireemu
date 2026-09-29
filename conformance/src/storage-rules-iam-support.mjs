import { EventEmitter } from "node:events";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ADC, NUMBERS, OWNER_TOKEN } from "./storage-rules-runner-support.mjs";
import { GRANT_ROLE, storageAgentMember } from "./storage-rules-iam/policy.mjs";

// A scratch code tree, and a fake `https.request` with a small IAM world: a policy with an etag that a setIamPolicy replaces when its etag matches.
export const SOURCE_COMMIT = "a".repeat(40);
export const PACKET_NAME = "stage2b-v1";
export const ENVELOPE_ID = "STORAGE-RULES-stage2b-v1-001";
export const PIN_KEYS = ["packetSha256", "sourceCommit", "runnerSha256", "manifestSha256", "fixtureSchemaSha256"];
export const OWNER_EMAIL = "owner@example.test";
export const OWNER_SUBJECT = "107364905517293846281";
export const ownerDigest = createHash("sha256").update(OWNER_EMAIL).digest("hex");
export const MEMBER = storageAgentMember(NUMBERS.query);
export const CODE_FILES = [
  "conformance/src/storage-rules/other.mjs", "conformance/src/storage-rules/nested/deep.mjs",
  "conformance/src/storage-rules-iam/policy.mjs", "conformance/src/storage-rules-iam/targets.mjs", "conformance/src/storage-rules-iam/run.mjs", "conformance/src/storage-rules-iam/nested/extra.mjs",
];

export function scratchCode() {
  const root = mkdtempSync("/private/tmp/storage-rules-iam-code-");
  for (const file of CODE_FILES) {
    mkdirSync(join(root, file, ".."), { recursive: true });
    writeFileSync(join(root, file), `export const name = ${JSON.stringify(file)};\n`);
  }
  return root;
}

export const OWNER_BINDING = { role: "roles/owner", members: [`user:${OWNER_EMAIL}`] };
export const OTHER_BINDINGS = [OWNER_BINDING, { role: "roles/firebase.admin", members: ["user:a@example.test", "user:b@example.test"] }, { role: "roles/editor", members: ["serviceAccount:x@example.test"], condition: { title: "temporary", expression: "request.time < timestamp('2030-01-01T00:00:00Z')" } }];
const clone = (value) => structuredClone(value);

/** A policy the fake production holds; `set` applies the request the way setIamPolicy does (etag must match, bindings replaced). */
export function createIamWorld({ bindings = OTHER_BINDINGS, etag = "BwYAAAAA" } = {}) {
  const world = { bindings: clone(bindings), etag, version: 3, sets: [], reads: 0, log: [], hook: {} };
  const policyBody = () => ({ version: world.version, etag: world.etag, bindings: clone(world.bindings), auditConfigs: [{ service: "allServices", auditLogConfigs: [{ logType: "ADMIN_READ" }] }] });
  world.policyBody = policyBody;
  world.bump = () => { world.etag = `${world.etag}x`; };
  world.answer = (spec) => {
    const url = new URL(spec.url);
    const json = (body, status = 200) => ({ status, rawHeaders: ["Content-Type", "application/json; charset=UTF-8"], bytes: Buffer.from(JSON.stringify(body)) });
    world.log.push(`${spec.method} ${url.pathname}`);
    if (url.host === "oauth2.googleapis.com" && url.pathname === "/token") return json({ access_token: OWNER_TOKEN, token_type: "Bearer", expires_in: 3600 });
    if (url.host === "www.googleapis.com" && url.pathname === "/oauth2/v2/userinfo") return json(world.hook.identity ?? { id: OWNER_SUBJECT, email: OWNER_EMAIL, verified_email: true });
    if (url.host === "cloudresourcemanager.googleapis.com" && url.pathname === `/v3/projects/${NUMBERS.query}:getIamPolicy`) {
      world.reads++;
      if (world.hook.beforeRead) world.hook.beforeRead(world);
      if (world.hook.read) { const replaced = world.hook.read(world, world.reads); if (replaced !== undefined) return replaced; }
      return json(policyBody());
    }
    if (url.host === "cloudresourcemanager.googleapis.com" && url.pathname === `/v3/projects/${NUMBERS.query}:setIamPolicy`) {
      const body = JSON.parse(spec.body.toString("utf8"));
      world.sets.push(body);
      if (world.hook.set) { const replaced = world.hook.set(world, body, world.sets.length); if (replaced !== undefined) return replaced; }
      if (body.policy.etag !== world.etag) return json({ error: { code: 409, status: "ABORTED", message: "etag mismatch" } }, 409);
      world.bindings = clone(body.policy.bindings);
      world.bump();
      return json(policyBody());
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

export function localInputs(adcPath) {
  return { schemaVersion: 1, adcPath, projectNumber: NUMBERS.query, ownerEmailSha256: ownerDigest };
}
export const cleanup = (path) => rmSync(path, { recursive: true, force: true });
export { ADC, GRANT_ROLE, NUMBERS, OWNER_TOKEN };
