import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createTransport } from "./functions-events/record/rest.mjs";
import { createTokenSource } from "./functions-events/record/token.mjs";

const adc = { type: "authorized_user", client_id: "id", client_secret: "SECRETVALUE", refresh_token: "REFRESHVALUE" };
const answerWith = (status, body) => ({ status, arrayBuffer: async () => Buffer.from(JSON.stringify(body)) });

function setup(replies) {
  let t = 0;
  const directory = mkdtempSync(join(tmpdir(), "fe-tok-"));
  const calls = [];
  const queue = [...replies];
  let source;
  const transport = createTransport({ directory, ceiling: 20, token: () => source(), apiKey: "k", now: () => t, fetch: async (url, init) => { calls.push({ url, init }); return queue.shift(); } });
  source = createTokenSource({ adc, request: transport.request, now: () => t });
  return { source, calls, advance: (ms) => { t += ms; }, directory, transport };
}

test("the token is refreshed through the transport, kept for 50 minutes, and counted", async () => {
  const { source, calls, advance, transport } = setup([answerWith(200, { access_token: "T1", expires_in: 3600 }), answerWith(200, { access_token: "T2" })]);
  assert.equal(await source(), "T1");
  assert.equal(await source(), "T1");
  assert.equal(calls.length, 1);
  assert.equal(transport.state.sent, 1);
  advance(51 * 60 * 1000);
  assert.equal(await source(), "T2");
  assert.equal(calls.length, 2);
  assert.equal(calls[0].init.headers.authorization, undefined);
  assert.match(String(calls[0].init.body), /grant_type=refresh_token/);
});

test("neither the secret, the refresh token nor the access token is written to the journal or the stored answer", async () => {
  const { source, directory } = setup([answerWith(200, { access_token: "ACCESSVALUE" })]);
  await source();
  const text = [readFileSync(join(directory, "journal.jsonl"), "utf8"), ...readdirSync(join(directory, "responses")).map((f) => readFileSync(join(directory, "responses", f), "utf8"))].join("\n");
  for (const secret of ["SECRETVALUE", "REFRESHVALUE", "ACCESSVALUE"]) assert.ok(!text.includes(secret), secret);
});

test("a refresh without an access token, an incomplete credential or another credential type is refused", async () => {
  const { source } = setup([answerWith(200, {}), answerWith(400, { error: "invalid_grant" })]);
  await assert.rejects(source(), /did not return/);
  await assert.rejects(source(), /did not return/);
  assert.throws(() => createTokenSource({ adc: { ...adc, refresh_token: "" }, request: async () => {} }), /incomplete/);
  assert.throws(() => createTokenSource({ adc: { ...adc, type: "service_account" }, request: async () => {} }), /not an authorized-user/);
});
