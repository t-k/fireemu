import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:http";
import { localOrigin, assertUrl, boundedText } from "../network.mjs";
import { runProcess, cleanEnvironment } from "../io.mjs";
const guardUrl = new URL("../network.mjs", import.meta.url).href;
async function server(handler, fn) {
  const s = createServer(handler);
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  try {
    return await fn(`http://127.0.0.1:${s.address().port}`);
  } finally {
    s.closeAllConnections();
    await new Promise((r) => s.close(r));
  }
}
const child = (code) =>
  runProcess(process.execPath, ["--input-type=module", "-e", code], {
    env: cleanEnvironment("/tmp"),
    timeoutMs: 4000,
  });
for (const host of [
  "localhost:8011",
  "firestore.googleapis.com:443",
  "127.0.0.1:0",
  "127.0.0.1:65536",
  "[::1]:8080",
  "127.0.0.1:8080/path",
])
  test(`reject endpoint ${host}`, () => assert.throws(() => localOrigin(host)));
test("only exact numeric loopback origin is accepted", () => {
  const origin = localOrigin("127.0.0.1:8080");
  assert.equal(assertUrl(origin + "/x", origin).pathname, "/x");
  for (const value of [
    "http://127.0.0.1:8081/x",
    "https://127.0.0.1:8080/x",
    "http://u:p@127.0.0.1:8080/x",
    "http://localhost:8080/x",
    origin + "/x#secret",
  ])
    assert.throws(() => assertUrl(value, origin));
});
test("real fetch succeeds on the owned loopback origin", async () => {
  await server(
    (q, r) => {
      r.setHeader("content-type", "application/json");
      r.end('{"ok":true}');
    },
    async (origin) => {
      const result = await child(`import {installNetworkGuard} from ${JSON.stringify(guardUrl)};
      installNetworkGuard(${JSON.stringify(origin)});
      console.log(JSON.stringify(await (await fetch(${JSON.stringify(origin + "/x")})).json()));`);
      assert.equal(result.code, 0, result.log.toString());
      assert.match(result.log.toString(), /"ok":true/);
    },
  );
});
test("redirect cannot reach a second loopback server", async () => {
  let reached = 0;
  await server(
    (q, r) => {
      reached++;
      r.end("bad");
    },
    async (target) => {
      await server(
        (q, r) => {
          r.writeHead(302, { location: target });
          r.end();
        },
        async (origin) => {
          const result = await child(`import {installNetworkGuard} from ${JSON.stringify(guardUrl)};
        installNetworkGuard(${JSON.stringify(origin)});
        try { await fetch(${JSON.stringify(origin)}); process.exitCode=3; }
        catch { console.log('redirect-refused'); }`);
          assert.equal(result.code, 0, result.log.toString());
          assert.equal(reached, 0);
        },
      );
    },
  );
});
test("off-origin fetch is rejected before any connection", async () => {
  let reached = 0;
  await server(
    (q, r) => {
      reached++;
      r.end("bad");
    },
    async (target) => {
      const result = await child(`import {installNetworkGuard} from ${JSON.stringify(guardUrl)};
      installNetworkGuard('http://127.0.0.1:1');
      try { await fetch(${JSON.stringify(target)}); process.exitCode=3; }
      catch { console.log('refused'); }`);
      assert.equal(result.code, 0, result.log.toString());
      assert.equal(reached, 0);
    },
  );
});
test("offline comparison denies network, DNS and credential commands", async () => {
  const result = await child(`import {installNetworkGuard} from ${JSON.stringify(guardUrl)};
    import http from 'node:http'; import https from 'node:https'; import net from 'node:net';
    import dns from 'node:dns'; import cp from 'node:child_process';
    installNetworkGuard();
    const probes = [()=>fetch('https://firestore.googleapis.com'),
      ()=>http.get('http://127.0.0.1:1'), ()=>https.get('https://example.com'),
      ()=>net.connect({host:'127.0.0.1',port:1}), ()=>dns.lookup('example.com',()=>{}),
      ()=>cp.execFileSync('gcloud',['auth','print-access-token']),
      ()=>cp.spawn('node',['-e','process.exit(0)'])];
    let rejected=0; for(const p of probes) { try { await p(); } catch { rejected++; } }
    console.log(rejected); if(rejected!==probes.length) process.exitCode=3;`);
  assert.equal(result.code, 0, result.log.toString());
  assert.equal(result.log.toString().trim(), "7");
});
test("response body size is bounded", async () => {
  assert.equal(await boundedText(new Response("abc"), 3), "abc");
  await assert.rejects(boundedText(new Response("abcd"), 3), /too-large/);
});
