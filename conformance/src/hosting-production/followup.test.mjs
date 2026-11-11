import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { brotliDecompressSync, gunzipSync } from "node:zlib";
import test from "node:test";

import { corpusManifest } from "./corpus.mjs";
import {
  buildFollowupCorpus,
  FOLLOWUP_CONDITIONS,
  FOLLOWUP_CORPUS_ID,
  FOLLOWUP_PROFILE,
  PRECOMPRESSED,
} from "./followup.mjs";
import { FOLLOWUP_CORPUS_SHA256 } from "./pins.mjs";

const corpus = buildFollowupCorpus();
const byId = Object.fromEntries(corpus.versions.map((v) => [v.id, v]));
const requests = corpus.versions.flatMap((v) => v.requests);

test("the follow-up corpus is five versions with the frozen request counts, and its digest is pinned", () => {
  assert.equal(corpus.corpusId, FOLLOWUP_CORPUS_ID);
  assert.deepEqual(
    corpus.versions.map((v) => [v.id, v.requests.length]),
    [
      ["v11", 22],
      ["v12", 11],
      ["v13", 3],
      ["v14", 10],
      ["v15", 32],
    ],
  );
  assert.equal(requests.length, 78);
  assert.equal(corpusManifest(corpus).corpusSha256, FOLLOWUP_CORPUS_SHA256);
  // it is another corpus than the one the HOSTING closure pinned
  assert.notEqual(
    FOLLOWUP_CORPUS_SHA256,
    "fa57f2b080426de0ea30e5b9758f117481a770561e625903974c4672fca43150",
  );
});

test("request ids are unique, carry their version, and name a known condition", () => {
  assert.equal(new Set(requests.map((r) => r.id)).size, requests.length);
  for (const version of corpus.versions) {
    for (const spec of version.requests) {
      assert.ok(spec.id.startsWith(`${version.id}.`), spec.id);
      assert.ok(FOLLOWUP_CONDITIONS.includes(spec.condition), `${spec.id}: ${spec.condition}`);
      assert.ok(spec.target.startsWith("/"), spec.id);
      assert.equal(
        spec.headers && Object.keys(spec.headers).every((k) => k === k.toLowerCase()),
        true,
        spec.id,
      );
    }
  }
});

test("every version serves its readiness file and an index, and the channel ids fit the recorder's host pattern", () => {
  for (const version of corpus.versions) {
    assert.match(version.id, /^v\d\d$/);
    assert.ok(version.files["ready.txt"], version.id);
    assert.ok(version.files["index.html"], version.id);
    assert.deepEqual(version.readiness, { path: "/ready.txt", accept: [200] });
  }
});

test("only the default 404 page and the hosted auth handler keep their body, and only v13 and v14 may be refused", () => {
  assert.deepEqual(
    requests.filter((r) => r.keepBody).map((r) => r.id),
    ["v11.default-404", "v11.auth-handler"],
  );
  assert.deepEqual(
    corpus.versions.filter((v) => v.mayRefuse).map((v) => v.id),
    ["v13", "v14"],
  );
  // the page the 404 probe reads must not be shadowed by a deployed 404.html
  assert.equal("404.html" in byId.v11.files, false);
});

test("v11 sends the frozen dot-segment and backslash targets, and the page probes", () => {
  const targets = Object.fromEntries(byId.v11.requests.map((r) => [r.id.slice(4), r.target]));
  assert.deepEqual(targets, {
    "default-404": "/missing",
    "default-404-json": "/missing.json",
    "default-404-nested": "/a/missing/deeper",
    "auth-handler": "/__/auth/handler",
    "auth-handler-query": "/__/auth/handler?mode=signIn",
    "dot-end-parent": "/a/b/..",
    "dot-mid-current": "/a/./b",
    "dot-end-current": "/a/b/.",
    "dot-dir-current": "/a/.",
    "dot-dir-parent": "/a/..",
    "dot-mid-parent": "/a/../a/b",
    "dot-lead-current": "/./a/b",
    "dot-encoded-current": "/a/%2e/b",
    "dot-encoded-end": "/a/b/%2e%2e",
    "backslash-mid": "/a\\b",
    "backslash-after-dot": "/a/./\\evil.example",
    "backslash-dot-first": "/.\\b",
    "backslash-lead": "/./\\evil",
    "backslash-encoded-after-dot": "/a/./%5cevil.example",
    "backslash-in-name": "/a/\\b",
    "dot-end-parent-slash": "/a/b/../",
    "dot-mid-current-slash": "/a/./b/",
  });
  assert.ok(byId.v11.files["a/b"] && byId.v11.files["a/index.html"]);
});

test("v12 and v13 probe digit-bearing and repeated redirect parameter names", () => {
  assert.deepEqual(
    byId.v12.hosting.redirects.map((r) => r.source),
    ["/capture/:id/:id2", "/p/:a1", "/s/:a1/x", "/t/:a1/:a2"],
  );
  assert.deepEqual(
    byId.v12.requests.map((r) => r.target),
    [
      "/capture/one/two2",
      "/capture/one/two",
      "/capture/x/:id2",
      "/capture/:id2/two",
      "/p/x",
      "/p/x1",
      "/p/:a1",
      "/s/v/x",
      "/s/:a1/x",
      "/t/u/v",
      "/t/1/2",
    ],
  );
  assert.deepEqual(byId.v13.hosting.redirects, [
    { source: "/q/:id/:id", destination: "/to-q/:id", type: 302 },
  ]);
  assert.deepEqual(
    byId.v13.requests.map((r) => r.target),
    ["/q/a/b", "/q/a/a", "/q/a"],
  );
});

test("v14 deploys real precompressed bytes with a Content-Encoding rule, v15 none", () => {
  const sourceText = "The quick brown fox jumps over the lazy dog.\n".repeat(100);
  assert.equal(brotliDecompressSync(PRECOMPRESSED.br).toString(), sourceText);
  assert.equal(gunzipSync(PRECOMPRESSED.gzip).toString(), sourceText);
  const files = byId.v14.files;
  assert.deepEqual(files["pre/big.txt.br"], PRECOMPRESSED.br);
  assert.deepEqual(files["pre/big.txt.gz"], PRECOMPRESSED.gzip);
  assert.deepEqual(files["pre/script.js"], PRECOMPRESSED.gzip);
  assert.equal(files["pre/plain.txt"].toString(), sourceText);
  assert.equal(files["pre/free.txt"].toString(), sourceText);
  assert.deepEqual(
    byId.v14.hosting.headers.map((h) => [h.source, h.headers[0].key, h.headers[0].value]),
    [
      ["/pre/*.br", "Content-Encoding", "br"],
      ["/pre/*.gz", "Content-Encoding", "gzip"],
      ["/pre/script.js", "Content-Encoding", "gzip"],
      ["/pre/plain.txt", "Content-Encoding", "identity"],
    ],
  );
  assert.equal(byId.v15.hosting.headers, undefined);
});

test("v15 probes sizes 1 to 4500 and thirteen content types with Accept-Encoding gzip, then the negotiation forms", () => {
  const files = byId.v15.files;
  for (const size of [1, 10, 100, 500, 1000, 1024, 1500, 2048, 4500]) {
    const name = `sz/s${String(size).padStart(4, "0")}.txt`;
    assert.equal(files[name].length, size, name);
  }
  const types = Object.keys(files).filter((name) => name.startsWith("t/"));
  assert.equal(types.length, 13);
  for (const name of types) assert.equal(files[name].length, 4500, name);
  const sizeRows = byId.v15.requests.filter((r) => r.id.startsWith("v15.size-"));
  const typeRows = byId.v15.requests.filter((r) => r.id.startsWith("v15.type-"));
  assert.equal(sizeRows.length, 9);
  assert.equal(typeRows.length, 13);
  for (const spec of [...sizeRows, ...typeRows]) {
    assert.equal(spec.method, "GET");
    assert.deepEqual(spec.headers, { "accept-encoding": "gzip" }, spec.id);
  }
  const negotiation = Object.fromEntries(
    byId.v15.requests
      .filter((r) => r.id.startsWith("v15.ae-") && r.id !== "v15.ae-cond")
      .map((r) => [r.id.slice(7), r.headers]),
  );
  assert.deepEqual(negotiation, {
    plain: {},
    star: { "accept-encoding": "*" },
    xgzip: { "accept-encoding": "x-gzip" },
    "gzip-q0": { "accept-encoding": "gzip;q=0" },
    identity: { "accept-encoding": "identity" },
    deflate: { "accept-encoding": "deflate" },
    upper: { "accept-encoding": "GZIP" },
    browser: { "accept-encoding": "gzip, deflate, br" },
    range: { "accept-encoding": "gzip", range: "bytes=0-9" },
  });
  // the conditional request takes its tag from the plain answer, which is sent before it
  const cond = byId.v15.requests.find((r) => r.id === "v15.ae-cond");
  assert.deepEqual(cond.headersFrom, [
    { header: "if-none-match", fromRequest: "v15.ae-plain", fromHeader: "etag" },
  ]);
  assert.equal(cond.headers["accept-encoding"], "gzip");
  const ids = byId.v15.requests.map((r) => r.id);
  assert.ok(ids.indexOf("v15.ae-plain") < ids.indexOf("v15.ae-cond"));
});

test("the profile names its own task, envelope, attempts, money and budget", () => {
  assert.equal(FOLLOWUP_PROFILE.taskId, "HOSTING-FOLLOWUP");
  assert.ok(FOLLOWUP_PROFILE.envelopePattern.test("HOSTING-FOLLOWUP-V1-20261111"));
  assert.equal(FOLLOWUP_PROFILE.envelopePattern.test("HOSTING-PRODUCTION-V5-20261111"), false);
  assert.equal(FOLLOWUP_PROFILE.maxAttempts, 3);
  assert.equal(FOLLOWUP_PROFILE.maxCumulativeUsd, 3);
  assert.equal(FOLLOWUP_PROFILE.reservedUsdPerAttempt, 1);
  assert.equal(FOLLOWUP_PROFILE.listFilesVersion, null);
  assert.equal(FOLLOWUP_PROFILE.corpusSha256, FOLLOWUP_CORPUS_SHA256);
});

test("the committed manifest is the corpus in its pinned form, and the pin is its digest", () => {
  const committed = JSON.parse(
    readFileSync(new URL("./followup.manifest.json", import.meta.url), "utf8"),
  );
  assert.deepEqual(committed, corpusManifest(corpus));
  assert.equal(committed.corpusSha256, FOLLOWUP_CORPUS_SHA256);
  assert.equal(committed.versions.length, 5);
});
