import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { compareCase, replay, replayCase } from "./rules-operators-replay.mjs";
const fixtureFile = new URL("./fixtures/production-rules-operators.json", import.meta.url);
const fixtureData = async () => JSON.parse(await readFile(fixtureFile));
test("recording contains all typed rows and full rules", async () => {
  const fixture = await fixtureData();
  assert.equal(fixture.rows.length, 98);
  assert.equal(new Set(fixture.rows.map(x => `${x.round}/${x.id}`)).size, 98);
  assert.ok(fixture.rules.r1["q-order-value-allow"][".indexOn"].includes(".value"));
  assert.equal(fixture.rows.filter(x => x.id === "add-null-input" && x.status === 401 && x.readback === null).length, 2);
  for (const row of fixture.rows) assert.equal(compareCase(row, structuredClone(row)).verdict, "MATCH");
});
test("typed results, request and predicate changes do not compare equal", async () => {
  const fixture = await fixtureData();
  const row = fixture.rows.find(x => x.id === "not-false-allow");
  for (const [key,value] of [["seed",0],["status",401],["predicate","true"],["readback",true]]) {
    const changed = structuredClone(row); changed[key]=value;
    assert.equal(compareCase(row, changed).verdict,"MISMATCH");
  }
});
test("invalid fixture performs no local I/O", async () => {
  let calls=0;
  await assert.rejects(replay("http://127.0.0.1:9000", {rows:[]}, {fetchImpl: async () => {calls++;}}));
  assert.equal(calls,0);
});
test("unresolved seed prevents client dispatch", async () => {
  const fixture = await fixtureData(); let calls=0;
  await assert.rejects(replayCase(fixture.rows[0], async () => {calls++;return {status:200,body:"null",etag:null};}, "localroot"));
  assert.equal(calls,1);
});

test("unknown dispatched seed stops all later cleanup requests", async () => {
  const fixture = JSON.parse(await readFile(new URL("./fixtures/production-rules-operators.json", import.meta.url)));
  const calls=[];
  await assert.rejects(replay("http://127.0.0.1:9000", fixture, {fetchImpl: async (url, options) => {
    calls.push([url,options.method ?? "GET"]);
    if (calls.length===3) throw Error("connection lost");
    return new Response(calls.length===1 ? "{}" : "{}", {status:200});
  }}), /unknown/);
  assert.equal(calls.length,3);
  assert.equal(calls[2][1],"PUT");
});
test("generated combinations exercise recorded case and transport", async () => {
  const fixture=JSON.parse(await readFile(new URL("./fixtures/production-rules-operators.json", import.meta.url)));
  const table=(await readFile(new URL("./fixtures/rules-operators-replay.generated.tsv", import.meta.url),"utf8")).trim().split("\n").slice(1);
  for (const line of table) {
    const [profile,round,kind,verdict,transport]=line.split("\t");
    assert.ok(["strict","ordinary"].includes(profile));
    const row=fixture.rows.find(x=>x.round===round && x.kind===kind && (x.status===200 ? "allow" : "deny")===verdict);
    assert.ok(row); let n=0;
    const send=async () => {
      n++;
      if(transport==="unknown") throw Error("transport unknown");
      if(n===1) return row.seedResponse;
      if(n===2) return {status:row.status,body:row.body,etag:row.etag};
      return {status:200,body:JSON.stringify(row.readback),etag:null};
    };
    if(transport==="unknown") await assert.rejects(replayCase(row,send,"localroot"),/unknown/);
    else assert.equal((await replayCase(row,send,"localroot")).result.verdict,"MATCH");
  }
});
test("tampered valid fixture is refused before local I/O", async () => {
  const fixture=await fixtureData(); fixture.rows[0].predicate="true"; let calls=0;
  await assert.rejects(replay("http://127.0.0.1:9000",fixture,{fetchImpl:async()=>{calls++;}}),/fixture invalid/);
  assert.equal(calls,0);
});
