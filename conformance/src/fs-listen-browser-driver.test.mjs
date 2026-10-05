import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

import {
  BUNDLES,
  FILES,
  allowedHosts,
  browserArgs,
  listenChannelCi,
  originOf,
} from "./fs-listen/browser-driver.mjs";

test("the page origin is http://localhost:<port>, the one the API key is restricted to", () => {
  assert.equal(originOf(47853), "http://localhost:47853");
});

test("a production page may reach the three Google hosts; a local page the emulators only", () => {
  assert.deepEqual(allowedHosts({ mode: "production" }), [
    "firestore.googleapis.com",
    "identitytoolkit.googleapis.com",
    "securetoken.googleapis.com",
  ]);
  assert.deepEqual(
    allowedHosts({
      mode: "local",
      authEmulator: "http://127.0.0.1:9099",
      firestoreEmulator: { host: "127.0.0.1", port: 8080 },
    }),
    ["127.0.0.1:9099", "127.0.0.1:8080"],
  );
});

test("only a local run switches Chromium's local network check off", () => {
  assert.deepEqual(browserArgs({ mode: "production" }), []);
  assert.deepEqual(browserArgs({}), []);
  assert.equal(browserArgs({ mode: "local" }).length, 1);
  assert.match(browserArgs({ mode: "local" })[0], /^--disable-features=.*LocalNetworkAccessChecks/);
});

test("listenChannelCi reads the CI of a Listen channel request and ignores every other URL", () => {
  const base = "http://h/google.firestore.v1.Firestore/Listen/channel";
  assert.equal(listenChannelCi(`${base}?VER=8&CI=1&RID=rpc`), "1");
  assert.equal(listenChannelCi(`${base}?VER=8&CI=0&RID=rpc`), "0");
  assert.equal(listenChannelCi(`${base}?VER=8&RID=1`), "none");
  assert.equal(listenChannelCi("http://h/google.firestore.v1.Firestore/Write/channel?CI=1"), null);
  assert.equal(
    listenChannelCi("https://identitytoolkit.googleapis.com/v1/accounts:lookup?CI=1"),
    null,
  );
});

test("the bundles the page may load are the three Firebase ones", () => {
  assert.deepEqual(BUNDLES, ["firebase-app.js", "firebase-auth.js", "firebase-firestore.js"]);
});

test("every file the page imports is served, exists, and no served module imports a Node built-in except the collector's crypto", () => {
  assert.ok(FILES["/"].body.includes('src="/lib/browser-page.mjs"'));
  assert.ok(FILES["/"].body.includes('"node:crypto":"/lib/sha256.js"'));
  const served = new Set(Object.keys(FILES));
  for (const [path, entry] of Object.entries(FILES)) {
    if (entry.file === undefined) continue;
    assert.ok(existsSync(entry.file), `${path} exists`);
    const source = readFileSync(entry.file, "utf8");
    for (const [, specifier] of source.matchAll(/^\s*(?:import|export)[^"']*from\s+"([^"]+)"/gm)) {
      if (specifier.startsWith("https://www.gstatic.com/firebasejs/12.18.0/")) {
        assert.ok(BUNDLES.includes(specifier.split("/").at(-1)), `${path}: ${specifier}`);
      } else if (specifier === "node:crypto") {
        assert.equal(path, "/lib/collector/listen_collector.mjs");
      } else if (specifier.startsWith("/")) {
        assert.ok(served.has(specifier), `${path} imports ${specifier}, which is not served`);
      } else if (specifier.startsWith("./")) {
        const dir = path.slice(0, path.lastIndexOf("/"));
        assert.ok(served.has(`${dir}/${specifier.slice(2)}`), `${path} imports ${specifier}`);
      } else {
        assert.fail(`${path} imports ${specifier}`);
      }
    }
    assert.equal(/node:(?!crypto)/.test(source), false, `${path} names a Node built-in`);
  }
});

test("the page pins the SDK version the driver serves", () => {
  const page = readFileSync(FILES["/lib/browser-page.mjs"].file, "utf8");
  const versions = [...page.matchAll(/firebasejs\/([0-9.]+)\//g)].map((m) => m[1]);
  assert.ok(versions.length >= 3);
  assert.deepEqual([...new Set(versions)], ["12.18.0"]);
});
