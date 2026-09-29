import assert from "node:assert/strict";
import test from "node:test";
import { createReleaseHttpsTransport, ROUTE_COUNT } from "./storage-rules-release/transport.mjs";
import { BUCKET, RELEASE_NAME, RULESET } from "./storage-rules-release-support.mjs";

// The stage 2c transport allows exact (method, path) routes with no query and nothing else.
const transport = createReleaseHttpsTransport({ requestImpl: () => { throw new Error("must not send"); } });
const spec = (method, url, body = null, headers = {}) => ({ url, method, headers, body });
const RULES = "https://firebaserules.googleapis.com";
const json = (value) => Buffer.from(JSON.stringify(value));
const allowed = [
  spec("POST", "https://oauth2.googleapis.com/token", Buffer.from("grant_type=refresh_token"), { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }),
  spec("GET", "https://www.googleapis.com/oauth2/v2/userinfo"),
  spec("GET", `${RULES}/v1/${RELEASE_NAME}`),
  spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/releases/firebase.storage`),
  spec("DELETE", `${RULES}/v1/${RELEASE_NAME}`),
  spec("POST", `${RULES}/v1/projects/fireemu-oracle-query/releases`, json({ name: RELEASE_NAME, rulesetName: RULESET }), { "content-type": "application/json; charset=utf-8" }),
  spec("GET", `${RULES}/v1/${RULESET}`),
];

test("every route the stage 2c runs use is allowed, and there are exactly that many routes", () => {
  assert.equal(ROUTE_COUNT, 6);
  for (const one of allowed) assert.doesNotThrow(() => transport.validate(one), `${one.method} ${one.url}`);
});

test("anything else is refused before it is counted: other methods, hosts, projects, paths, queries and shapes", () => {
  const refused = [
    spec("POST", `${RULES}/v1/${RELEASE_NAME}`, json({})), spec("PATCH", `${RULES}/v1/${RELEASE_NAME}`, json({})), spec("PUT", `${RULES}/v1/${RELEASE_NAME}`, json({})),
    spec("DELETE", `${RULES}/v1/projects/fireemu-oracle-query/releases/firebase.storage`), spec("DELETE", `${RULES}/v1/${RULESET}`), spec("DELETE", `${RULES}/v1/projects/fireemu-oracle-query/releases`),
    spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/releases`), spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/rulesets`), spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/releases/firebase.storage/`),
    spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/releases/firebase.storage/Bad`), spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/releases/firebase.storage/${BUCKET}/x`),
    spec("GET", `${RULES}/v1/projects/other/releases/firebase.storage/${BUCKET}`), spec("GET", `${RULES}/v1/projects/other/rulesets/x`), spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/rulesets/a/b`),
    spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/releases/firebase.storage/${BUCKET}?updateMask=x`), spec("GET", `${RULES}/v1/${RULESET}?x=1`), spec("GET", "https://www.googleapis.com/oauth2/v2/userinfo?alt=json"),
    spec("POST", "https://www.googleapis.com/oauth2/v2/userinfo", json({})), spec("GET", "https://www.googleapis.com/oauth2/v3/userinfo"),
    spec("GET", "https://oauth2.googleapis.com/token"), spec("POST", "https://oauth2.googleapis.com/tokeninfo", Buffer.from("x")), spec("POST", "https://oauth2.googleapis.com/token?x=1", Buffer.from("x")),
    spec("GET", "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"),
    spec("GET", `https://cloudresourcemanager.googleapis.com/v3/projects/123`), spec("POST", "https://cloudresourcemanager.googleapis.com/v3/projects/123:setIamPolicy", json({})),
    spec("GET", `https://storage.googleapis.com/storage/v1/b/${BUCKET}`), spec("GET", "https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)"),
    spec("GET", `http://firebaserules.googleapis.com/v1/${RELEASE_NAME}`), spec("GET", `https://firebaserules.googleapis.com:443/v1/${RELEASE_NAME}`), spec("GET", `https://user@firebaserules.googleapis.com/v1/${RELEASE_NAME}`),
    spec("GET", `${RULES}/v1/${RELEASE_NAME}#x`), spec("GET", `${RULES}/v1/${RELEASE_NAME}`, json({})), spec("DELETE", `${RULES}/v1/${RELEASE_NAME}`, json({})),
    spec("GET", `https://FIREBASERULES.googleapis.com/v1/${RELEASE_NAME}`), spec("GET", `${RULES}/v1/${RELEASE_NAME.replace("firebase.storage", "firebaseXstorage")}`),
  ];
  for (const one of refused) assert.throws(() => transport.validate(one), (error) => error.notSent === true && /invalid HTTP transport input/.test(error.message), `${one.method} ${one.url}`);
});

test("the route patterns are exact at their edges: bucket and ruleset lengths and characters, anchoring, project and origin", () => {
  const release = (bucket) => spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/releases/firebase.storage/${bucket}`);
  for (const bucket of ["abc", "a.b", "0-_", "a".repeat(222)]) assert.doesNotThrow(() => transport.validate(release(bucket)), bucket);
  for (const bucket of ["ab", "a", "aBc", "abC", "-bc", "a".repeat(223), "a/b", "a b", "a%20b", "ab$"]) assert.throws(() => transport.validate(release(bucket)), /invalid HTTP transport input/, bucket);
  assert.throws(() => transport.validate(spec("DELETE", release("ab").url)), /invalid HTTP transport input/);
  assert.throws(() => transport.validate(spec("DELETE", release("aBc").url)), /invalid HTTP transport input/);
  for (const bad of [
    `${RULES}/v1/projects/fireemu-oracle-query/releases/firebase.storage/${BUCKET}/${BUCKET}`, `${RULES}/foo/v1/projects/fireemu-oracle-query/releases/firebase.storage/${BUCKET}`, `${RULES}/x/v1/projects/fireemu-oracle-query/rulesets/abc`,
    `${RULES}/v1/projects/fireemu-oracle-query/releases/firebaseXstorage/${BUCKET}`, "https://storage.googleapis.com/v1/projects/fireemu-oracle-query/releases/firebase.storage/x-bucket", "https://firebaserules.example.com/v1/projects/fireemu-oracle-query/releases/firebase.storage/x-bucket",
    "https://www.googleapis.com/v1/projects/fireemu-oracle-query/releases/firebase.storage/x-bucket", `${RULES}/v1/projects/fireemu-oracle-query/rulesets/${"a".repeat(129)}`, `${RULES}/v1/projects/fireemu-oracle-query/rulesets/a.b`, `${RULES}/v1/projects/fireemu-oracle-query/rulesets/a%2Fb`,
  ]) assert.throws(() => transport.validate(spec("GET", bad)), /invalid HTTP transport input/, bad);
  assert.doesNotThrow(() => transport.validate(spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/rulesets/${"a".repeat(128)}`)));
  assert.doesNotThrow(() => transport.validate(spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/rulesets/a_b-C9`)));
  for (const url of [`${RULES}/v1/projects/other/releases`, `${RULES}/x/v1/projects/fireemu-oracle-query/releases`, `${RULES}/v1/projects/fireemu-oracle-query/releases/`, "https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/releases", "https://oauth2.googleapis.com/v1/projects/fireemu-oracle-query/releases"]) {
    assert.throws(() => transport.validate(spec("POST", url, json({}))), /invalid HTTP transport input/, url);
  }
  // A path that fits one route never fits another method or origin.
  assert.throws(() => transport.validate(spec("GET", "https://firebaserules.googleapis.com/token")), /invalid HTTP transport input/);
  assert.throws(() => transport.validate(spec("POST", "https://www.googleapis.com/token", Buffer.from("x"))), /invalid HTTP transport input/);
  assert.throws(() => transport.validate(spec("GET", "https://oauth2.googleapis.com/oauth2/v2/userinfo")), /invalid HTTP transport input/);
});

test("the input record is closed and the headers are plain, bounded and lower-case", () => {
  const good = allowed[2];
  for (const bad of [null, undefined, {}, { ...good, extra: 1 }, { ...good, headers: null }, { ...good, headers: { Authorization: "x" } }, { ...good, headers: { host: "evil" } }, { ...good, headers: { "content-length": "1" } }, { ...good, headers: { a: "x\ny" } }, { ...good, method: "TRACE" }, { ...good, url: 5 }, { ...good, body: "text" }]) {
    assert.throws(() => transport.validate(bad), /invalid HTTP transport input/);
  }
  assert.throws(() => createReleaseHttpsTransport({}), /invalid HTTP transport input/);
  assert.throws(() => createReleaseHttpsTransport({ requestImpl: 5 }), /invalid HTTP transport input/);
  assert.throws(() => createReleaseHttpsTransport({ requestImpl() {}, extra: 1 }), /invalid HTTP transport input/);
});
