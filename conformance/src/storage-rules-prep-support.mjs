import { EventEmitter } from "node:events";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ADC, API_KEYS, BUCKET, KEY_IDS, NUMBERS, OWNER_TOKEN, preflightAnswer } from "./storage-rules-runner-support.mjs";
import { prepCorpus } from "./storage-rules-prep/plan.mjs";
import { prepCodeDigests } from "./storage-rules-prep/pins.mjs";

// A scratch main checkout, a scratch code tree, the operator's local inputs file and a fake `https.request` for the stage 2a reads.
export const SOURCE_COMMIT = "a".repeat(40);
export const PACKET_NAME = "stage2a-v1";
export const ENVELOPE_ID = "STORAGE-RULES-stage2a-v1-001";
export const PIN_KEYS = ["packetSha256", "sourceCommit", "runnerSha256", "manifestSha256", "fixtureSchemaSha256"];
export const CODE_FILES = [
  "conformance/src/storage-rules/private-inputs.mjs", "conformance/src/storage-rules/acceptance-preflight.mjs", "conformance/src/storage-rules/acceptance-core.mjs", "conformance/src/storage-rules/other.mjs",
  "conformance/src/storage-rules-prep/plan.mjs", "conformance/src/storage-rules-prep/nested/extra.mjs", "spec/compatibility/closure/STORAGE-RULES.json",
];

export function scratchCode(closureText) {
  const root = mkdtempSync("/private/tmp/storage-rules-prep-code-");
  for (const file of CODE_FILES) {
    mkdirSync(join(root, file, ".."), { recursive: true });
    writeFileSync(join(root, file), file.endsWith(".json") ? closureText : `export const name = ${JSON.stringify(file)};\n`);
  }
  return root;
}

export const keyListBody = (which, number, extra = {}) => ({ keys: [{ name: `projects/${number}/locations/global/keys/${KEY_IDS[which]}`, uid: `${which}-key-uid`, restrictions: { apiTargets: [{ service: "identitytoolkit.googleapis.com" }] } }], ...extra });

/** What production answers for the thirteen reads when everything matches; `bad` replaces the body of one route by name. */
export function prepAnswer(spec, bad = {}) {
  const url = new URL(spec.url);
  const json = (body, status = 200) => ({ status, rawHeaders: ["Content-Type", "application/json; charset=UTF-8"], bytes: Buffer.from(JSON.stringify(body)) });
  if (url.host === "oauth2.googleapis.com" && url.pathname === "/token") return { status: 200, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from(JSON.stringify({ access_token: OWNER_TOKEN, token_type: "Bearer", expires_in: 3600 })) };
  const list = /^\/v2\/projects\/(\d+)\/locations\/global\/keys$/.exec(url.pathname);
  if (url.host === "apikeys.googleapis.com" && list) {
    const which = list[1] === NUMBERS.query ? "query" : "idp";
    return json(bad[`list-${which}`] ?? keyListBody(which, list[1]));
  }
  const answer = preflightAnswer(spec, bad);
  if (answer === undefined) throw new Error(`unexpected route ${spec.url}`);
  return answer;
}

/** A fake `https.request`: records each attempt and answers from `answer`. */
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
  return { schemaVersion: 1, adcPath, projects: { query: { projectNumber: NUMBERS.query, apiKey: API_KEYS.query }, idp: { projectNumber: NUMBERS.idp, apiKey: API_KEYS.idp } }, bucket: { name: BUCKET } };
}

export const cleanup = (path) => rmSync(path, { recursive: true, force: true });
export { ADC, chmodSync, prepCorpus, prepCodeDigests, mkdirSync, mkdtempSync, writeFileSync, join };
