import assert from "node:assert/strict";
import test from "node:test";
import { createProbeHttpsTransport, ROUTE_COUNT } from "./storage-rules-probe/transport.mjs";
import { BUCKET } from "./storage-rules-probe-support.mjs";

// The stage 2d transport allows exact (method, path, query) routes and nothing else.
const transport = createProbeHttpsTransport({ requestImpl: () => { throw new Error("must not send"); } });
const spec = (method, url, body = null, headers = {}) => ({ url, method, headers, body });
const RULES = "https://firebaserules.googleapis.com";
const GCS = "https://storage.googleapis.com";
const object = `${GCS}/storage/v1/b/${BUCKET}/o/STORAGE-RULES%2Fprobe-2d%2Fabsent-object.bin`;
const json = (value) => Buffer.from(JSON.stringify(value));
const allowed = [
  spec("POST", "https://oauth2.googleapis.com/token", Buffer.from("grant_type=refresh_token"), { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }),
  spec("GET", "https://www.googleapis.com/oauth2/v2/userinfo"),
  spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/rulesets?pageSize=100`),
  spec("GET", object),
  spec("GET", `${object}?alt=media`),
  spec("POST", `${RULES}/v1/projects/fireemu-oracle-query:test`, json({ source: { files: [] } }), { "content-type": "application/json; charset=utf-8" }),
  spec("GET", "https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES/probe-2d-absent-document"),
];

test("every route the probe uses is allowed, and there are exactly that many routes", () => {
  assert.equal(ROUTE_COUNT, allowed.length);
  for (const one of allowed) assert.doesNotThrow(() => transport.validate(one), `${one.method} ${one.url}`);
});

test("anything else is refused before it is counted: other methods, hosts, projects, names, queries and shapes", () => {
  const refused = [
    spec("POST", object, json({})), spec("DELETE", object), spec("PATCH", object, json({})), spec("PUT", object, json({})),
    spec("GET", `${object}?alt=json`), spec("GET", `${object}?alt=media&x=1`), spec("GET", `${object}?`), spec("GET", `${object}#x`), spec("GET", `${object}?alt=media#x`),
    spec("GET", `${GCS}/storage/v1/b/${BUCKET}/o/STORAGE-RULES%2Fprobe-2d%2Fother.bin`), spec("GET", `${GCS}/storage/v1/b/${BUCKET}/o/STORAGE-RULES%2Frun-1%2Fcontrol-0`),
    spec("GET", `${GCS}/storage/v1/b/Bad/o/STORAGE-RULES%2Fprobe-2d%2Fabsent-object.bin`), spec("GET", `${GCS}/storage/v1/b/${BUCKET}`), spec("GET", `${GCS}/storage/v1/b/${BUCKET}/iam`), spec("GET", `${GCS}/storage/v1/b/${BUCKET}/o`),
    spec("GET", `${GCS}/upload/storage/v1/b/${BUCKET}/o/STORAGE-RULES%2Fprobe-2d%2Fabsent-object.bin`), spec("GET", `https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o/STORAGE-RULES%2Fprobe-2d%2Fabsent-object.bin`),
    spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/rulesets`), spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/rulesets?pageSize=10`), spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/rulesets?pageSize=100&pageToken=x`),
    spec("POST", `${RULES}/v1/projects/fireemu-oracle-query/rulesets`, json({})), spec("GET", `${RULES}/v1/projects/other/rulesets?pageSize=100`), spec("DELETE", `${RULES}/v1/projects/fireemu-oracle-query/rulesets/abc`),
    spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/releases`), spec("POST", `${RULES}/v1/projects/fireemu-oracle-query/releases`, json({})),
    spec("GET", `${RULES}/v1/projects/fireemu-oracle-query:test`), spec("POST", `${RULES}/v1/projects/other:test`, json({})), spec("POST", `${RULES}/v1/projects/fireemu-oracle-query:test?x=1`, json({})), spec("POST", `${RULES}/x/v1/projects/fireemu-oracle-query:test`, json({})),
    spec("GET", "https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES/other"), spec("DELETE", "https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES/probe-2d-absent-document"),
    spec("POST", "https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES/probe-2d-absent-document", json({})), spec("GET", "https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES/probe-2d-absent-document?x=1"),
    spec("GET", "https://firestore.googleapis.com/v1/projects/other/databases/(default)/documents/STORAGE-RULES/probe-2d-absent-document"),
    spec("GET", "https://oauth2.googleapis.com/token"), spec("POST", "https://oauth2.googleapis.com/tokeninfo", Buffer.from("x")), spec("POST", "https://oauth2.googleapis.com/token?x=1", Buffer.from("x")),
    spec("GET", "https://www.googleapis.com/oauth2/v2/userinfo?alt=json"), spec("POST", "https://www.googleapis.com/oauth2/v2/userinfo", json({})), spec("GET", "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"),
    spec("GET", "https://cloudresourcemanager.googleapis.com/v3/projects/123"), spec("POST", "https://cloudresourcemanager.googleapis.com/v3/projects/123:setIamPolicy", json({})),
    spec("GET", "http://storage.googleapis.com/x"), spec("GET", `https://user@storage.googleapis.com/storage/v1/b/${BUCKET}/o/STORAGE-RULES%2Fprobe-2d%2Fabsent-object.bin`), spec("GET", `https://storage.googleapis.com:443/storage/v1/b/${BUCKET}/o/STORAGE-RULES%2Fprobe-2d%2Fabsent-object.bin`),
    spec("GET", `${object}`, json({})),
  ];
  for (const one of refused) assert.throws(() => transport.validate(one), (error) => error.notSent === true && /invalid HTTP transport input/.test(error.message), `${one.method} ${one.url}`);
});

test("a path that fits one route never fits another method, origin or query", () => {
  assert.throws(() => transport.validate(spec("GET", "https://firebaserules.googleapis.com/token")), /invalid HTTP transport input/);
  assert.throws(() => transport.validate(spec("POST", "https://www.googleapis.com/token", Buffer.from("x"))), /invalid HTTP transport input/);
  assert.throws(() => transport.validate(spec("GET", "https://oauth2.googleapis.com/oauth2/v2/userinfo")), /invalid HTTP transport input/);
  assert.throws(() => transport.validate(spec("GET", object.replace(GCS, RULES))), /invalid HTTP transport input/);
  assert.throws(() => transport.validate(spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/rulesets?pageSize=100`.replace(RULES, GCS))), /invalid HTTP transport input/);
});

test("the input record is closed and the headers are plain, bounded and lower-case", () => {
  const good = allowed[2];
  for (const bad of [null, undefined, {}, { ...good, extra: 1 }, { ...good, headers: null }, { ...good, headers: { Authorization: "x" } }, { ...good, headers: { host: "evil" } }, { ...good, headers: { "content-length": "1" } }, { ...good, headers: { a: "x\ny" } }, { ...good, method: "TRACE" }, { ...good, url: 5 }, { ...good, body: "text" }]) assert.throws(() => transport.validate(bad), /invalid HTTP transport input/);
  assert.throws(() => createProbeHttpsTransport({}), /invalid HTTP transport input/);
  assert.throws(() => createProbeHttpsTransport({ requestImpl: 5 }), /invalid HTTP transport input/);
  assert.throws(() => createProbeHttpsTransport({ requestImpl() {}, extra: 1 }), /invalid HTTP transport input/);
});
