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

test("the input record is closed and the headers are plain, bounded and lower-case", () => {
  const good = allowed[2];
  for (const bad of [null, undefined, {}, { ...good, extra: 1 }, { ...good, headers: null }, { ...good, headers: { Authorization: "x" } }, { ...good, headers: { host: "evil" } }, { ...good, headers: { "content-length": "1" } }, { ...good, headers: { a: "x\ny" } }, { ...good, method: "TRACE" }, { ...good, url: 5 }, { ...good, body: "text" }]) {
    assert.throws(() => transport.validate(bad), /invalid HTTP transport input/);
  }
  assert.throws(() => createReleaseHttpsTransport({}), /invalid HTTP transport input/);
  assert.throws(() => createReleaseHttpsTransport({ requestImpl: 5 }), /invalid HTTP transport input/);
  assert.throws(() => createReleaseHttpsTransport({ requestImpl() {}, extra: 1 }), /invalid HTTP transport input/);
});
