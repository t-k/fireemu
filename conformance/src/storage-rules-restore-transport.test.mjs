import assert from "node:assert/strict";
import test from "node:test";
import { ALLOWED_LIMIT, createRestoreHttpsTransport } from "./storage-rules-restore/transport.mjs";
import { restoreRequests } from "./storage-rules-restore/plan.mjs";
import { parseState } from "./storage-rules-restore/state.mjs";
import { fakeRequestImpl, BUCKET, STATE } from "./storage-rules-restore-support.mjs";

// The stage 2e transport allows exactly the planned `METHOD URL` pairs plus the token refresh and the identity read, and nothing else.
const planned = restoreRequests(parseState(STATE));
const transport = createRestoreHttpsTransport({ requestImpl: () => { throw new Error("must not send"); }, planned });
const spec = (method, url, body = null, headers = {}) => ({ url, method, headers, body });
const json = (value) => Buffer.from(JSON.stringify(value));
const GCS = "https://storage.googleapis.com";
const RULES = "https://firebaserules.googleapis.com";
const asSpec = (entry) => spec(entry.method, entry.url, entry.body, entry.body === null ? {} : { "content-type": "application/json; charset=utf-8" });

test("every planned request, the token refresh and the identity read are allowed", () => {
  for (const entry of planned) assert.doesNotThrow(() => transport.validate(asSpec(entry)), `${entry.method} ${entry.url}`);
  assert.doesNotThrow(() => transport.validate(spec("POST", "https://oauth2.googleapis.com/token", Buffer.from("grant_type=refresh_token"), { "content-type": "application/x-www-form-urlencoded" })));
  assert.doesNotThrow(() => transport.validate(spec("GET", "https://www.googleapis.com/oauth2/v2/userinfo")));
});

test("anything that is not planned is refused before it is counted: another method, object, ruleset, account, query or shape", () => {
  const object = `${GCS}/storage/v1/b/${BUCKET}/o/${encodeURIComponent(STATE.objects[0].name)}`;
  const kept = "projects/fireemu-oracle-query/rulesets/22b746af-0000-4000-8000-000000000000";
  const refused = [
    spec("DELETE", object), spec("DELETE", `${object}?ifGenerationMatch=1`), spec("DELETE", `${object}?ifGenerationMatch=${STATE.objects[1].generation}`), spec("PATCH", object, json({})), spec("PUT", object, json({})), spec("POST", object, json({})),
    spec("GET", `${object}?alt=media`), spec("GET", `${object}?`), spec("GET", `${object}#x`),
    spec("GET", `${GCS}/storage/v1/b/${BUCKET}/o/${encodeURIComponent("STORAGE-RULES/other/x")}`), spec("DELETE", `${GCS}/storage/v1/b/${BUCKET}/o/${encodeURIComponent("STORAGE-RULES/other/x")}?ifGenerationMatch=1`),
    spec("GET", `${GCS}/storage/v1/b/other/o/${encodeURIComponent(STATE.objects[0].name)}`), spec("GET", `${GCS}/storage/v1/b/${BUCKET}/o`), spec("GET", `${GCS}/storage/v1/b/${BUCKET}/o?prefix=STORAGE-RULES%2F&maxResults=1`), spec("GET", `${GCS}/storage/v1/b/${BUCKET}`),
    spec("DELETE", `${RULES}/v1/${kept}`), spec("DELETE", `${RULES}/v1/${STATE.rulesets[0]}?x=1`), spec("GET", `${RULES}/v1/${STATE.rulesets[0]}`), spec("POST", `${RULES}/v1/${STATE.rulesets[0]}`, json({})),
    spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/rulesets`), spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/rulesets?pageSize=10`), spec("POST", `${RULES}/v1/projects/fireemu-oracle-query/rulesets`, json({})),
    spec("DELETE", `${RULES}/v1/projects/fireemu-oracle-query/releases/firebase.storage/${BUCKET}`), spec("DELETE", `${RULES}/v1/projects/fireemu-oracle-query/releases/firebase.storage`), spec("PATCH", `${RULES}/v1/projects/fireemu-oracle-query/releases/firebase.storage/${BUCKET}`, json({})), spec("POST", `${RULES}/v1/projects/fireemu-oracle-query/releases`, json({})),
    spec("POST", "https://identitytoolkit.googleapis.com/v1/projects/fireemu-oracle-query/accounts:delete", json({ localId: "someone-else" })), spec("POST", "https://identitytoolkit.googleapis.com/v1/projects/fireemu-oracle-query/accounts:lookup?x=1", json({ localId: STATE.accounts })),
    spec("POST", "https://identitytoolkit.googleapis.com/v1/projects/other/accounts:delete", json({ localId: STATE.accounts[0] })), spec("GET", "https://identitytoolkit.googleapis.com/v1/projects/fireemu-oracle-query/accounts:delete"), spec("POST", "https://identitytoolkit.googleapis.com/v1/projects/fireemu-oracle-query/accounts:batchDelete", json({})),
    spec("POST", "https://identitytoolkit.googleapis.com/v1/projects/fireemu-oracle-query/accounts", json({})), spec("POST", "https://identitytoolkit.googleapis.com/v1/projects/fireemu-oracle-query/accounts:signUp", json({})),
    spec("GET", "https://oauth2.googleapis.com/token"), spec("POST", "https://oauth2.googleapis.com/token?x=1", Buffer.from("x")), spec("GET", "https://www.googleapis.com/oauth2/v2/userinfo?alt=json"), spec("POST", "https://www.googleapis.com/oauth2/v2/userinfo", json({})),
    spec("GET", "https://cloudresourcemanager.googleapis.com/v3/projects/123"), spec("POST", "https://cloudresourcemanager.googleapis.com/v3/projects/123:setIamPolicy", json({})),
    spec("GET", "http://storage.googleapis.com/x"), spec("GET", `https://user@storage.googleapis.com/storage/v1/b/${BUCKET}/o/${encodeURIComponent(STATE.objects[0].name)}`), spec("GET", `${GCS}:443/storage/v1/b/${BUCKET}/o/${encodeURIComponent(STATE.objects[0].name)}`),
    spec("GET", `${object}`, json({})), spec("DELETE", `${object}?ifGenerationMatch=${STATE.objects[0].generation}`, json({})),
  ];
  for (const one of refused) assert.throws(() => transport.validate(one), (error) => error.notSent === true && /invalid HTTP transport input/.test(error.message), `${one.method} ${one.url}`);
});

test("a planned request sent with the wrong method or with another body-carrying method is refused", () => {
  for (const entry of planned) {
    const other = entry.method === "GET" ? "DELETE" : "GET";
    assert.throws(() => transport.validate(spec(other, entry.url)), /invalid HTTP transport input/, entry.id);
    assert.throws(() => transport.validate(spec("PUT", entry.url, json({}))), /invalid HTTP transport input/, entry.id);
  }
});

test("the input record is closed, the headers are plain, bounded and lower-case, and the allowed set has a size limit", () => {
  const good = asSpec(planned[3]);
  for (const bad of [null, undefined, {}, { ...good, extra: 1 }, { ...good, headers: null }, { ...good, headers: { Authorization: "x" } }, { ...good, headers: { host: "evil" } }, { ...good, headers: { "content-length": "1" } }, { ...good, headers: { a: "x\ny" } }, { ...good, method: "TRACE" }, { ...good, url: 5 }, { ...good, body: "text" }]) assert.throws(() => transport.validate(bad), /invalid HTTP transport input/);
  for (const bad of [{}, { requestImpl: 5, planned }, { requestImpl() {}, planned: "x" }, { requestImpl() {}, planned: [{ method: "GET" }] }, { requestImpl() {}, planned: [null] }, { requestImpl() {}, planned, extra: 1 }, { requestImpl() {} }, { planned }]) assert.throws(() => createRestoreHttpsTransport(bad), /invalid HTTP transport input/);
  assert.equal(ALLOWED_LIMIT, 200);
  const many = Array.from({ length: ALLOWED_LIMIT + 1 }, (_, index) => ({ method: "GET", url: `https://storage.googleapis.com/x/${index}` }));
  assert.throws(() => createRestoreHttpsTransport({ requestImpl() {}, planned: many }), /invalid HTTP transport input/);
  assert.doesNotThrow(() => createRestoreHttpsTransport({ requestImpl() {}, planned: many.slice(0, ALLOWED_LIMIT) }));
});

test("a planned request is sent as issued: method, exact URL, identity encoding and the body's length", async () => {
  const seen = [];
  const send = createRestoreHttpsTransport({ requestImpl: fakeRequestImpl(() => ({ status: 204, rawHeaders: [], bytes: Buffer.alloc(0) }), seen), planned });
  const del = planned.find((entry) => entry.id === "cleanup/object/0/delete");
  const answer = await send.send(asSpec(del));
  assert.equal(answer.status, 204);
  const account = planned.find((entry) => entry.id === "cleanup/account/0/delete");
  await send.send(asSpec(account));
  assert.deepEqual(seen.map((entry) => [entry.method, entry.url]), [["DELETE", del.url], ["POST", account.url]]);
  assert.equal(seen[0].headers["accept-encoding"], "identity");
  assert.equal(seen[0].headers["content-length"], undefined);
  assert.equal(seen[1].headers["content-length"], String(account.body.length));
  await assert.rejects(send.send(spec("DELETE", `${del.url}0`)), (error) => error.notSent === true);
  assert.equal(seen.length, 2);
});
