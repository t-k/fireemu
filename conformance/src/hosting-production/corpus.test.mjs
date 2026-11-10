import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  CONDITIONS,
  CONTENT_TYPE_EXTENSIONS,
  GLOB_PATHS,
  GLOB_PATTERNS,
  buildCorpus,
  corpusCounts,
  corpusManifest,
  globHeader,
} from "./corpus.mjs";

const corpus = buildCorpus();
const requests = corpus.versions.flatMap((v) => v.requests);

test("the committed manifest is the corpus (parsed, so formatting does not matter)", async () => {
  const committed = JSON.parse(
    await readFile(new URL("./corpus.manifest.json", import.meta.url), "utf8"),
  );
  assert.deepEqual(committed, JSON.parse(JSON.stringify(corpusManifest())));
  assert.match(committed.corpusSha256, /^[0-9a-f]{64}$/);
});

test("ten versions in a fixed order, each with a tree, readiness and requests", () => {
  assert.deepEqual(
    corpus.versions.map((v) => v.id),
    ["v01", "v02", "v03", "v04", "v05", "v06", "v07", "v08", "v09", "v10"],
  );
  for (const version of corpus.versions) {
    assert.ok(version.files["ready.txt"], `${version.id} has the readiness file`);
    assert.ok(version.requests.length > 0);
    assert.ok(version.readiness.accept.every((s) => Number.isInteger(s)));
    assert.equal(
      version.hosting.public,
      undefined,
      "public is set by the recorder, not the corpus",
    );
  }
});

test("request ids are unique and carry their version prefix; conditions are known", () => {
  const ids = new Set();
  for (const version of corpus.versions) {
    for (const request of version.requests) {
      assert.ok(request.id.startsWith(`${version.id}.`), request.id);
      assert.ok(!ids.has(request.id), `duplicate ${request.id}`);
      ids.add(request.id);
      assert.ok(CONDITIONS.includes(request.condition), request.id);
      for (const also of request.also ?? []) assert.ok(CONDITIONS.includes(also), request.id);
      assert.match(request.method, /^(GET|HEAD|POST|PUT|DELETE|OPTIONS)$/);
      assert.ok(request.target.startsWith("/"), request.id);
      assert.deepEqual(
        Object.keys(request.headers).filter((k) => k !== k.toLowerCase()),
        [],
        `${request.id} header names are lower-case`,
      );
    }
  }
});

test("a dependent header names an earlier request of the same version", () => {
  for (const version of corpus.versions) {
    const seen = new Set();
    for (const request of version.requests) {
      for (const dep of request.headersFrom ?? []) {
        assert.ok(seen.has(dep.fromRequest), `${request.id} depends on a later ${dep.fromRequest}`);
        assert.ok(dep.fromRequest.startsWith(`${version.id}.`));
      }
      seen.add(request.id);
    }
  }
});

test("nothing in the corpus needs a deployed upstream or a project-specific value", () => {
  const json = JSON.stringify(corpus.versions.map((v) => v.hosting));
  assert.doesNotMatch(json, /"function"|"run"|dynamicLinks/);
  assert.doesNotMatch(
    JSON.stringify([corpus.versions.map((v) => v.hosting), requests]),
    /fireemu-oracle|\d{12}/,
  );
});

test("every closure condition that needs production has requests; path-safety is information only", () => {
  const counts = new Map();
  for (const request of requests) {
    for (const condition of [request.condition, ...(request.also ?? [])]) {
      counts.set(condition, (counts.get(condition) ?? 0) + 1);
    }
  }
  for (const condition of CONDITIONS) assert.ok(counts.get(condition) > 0, condition);
  assert.ok(requests.filter((r) => r.condition === "path-safety").every((r) => r.infoOnly));
  assert.ok(requests.filter((r) => r.infoOnly).every((r) => r.condition === "path-safety"));
});

test("the glob version has one header rule per pattern and one request per path", () => {
  const glob = corpus.versions.find((v) => v.id === "v10");
  assert.equal(glob.hosting.headers.length, GLOB_PATTERNS.length);
  glob.hosting.headers.forEach((rule, index) => {
    assert.equal(rule.source, GLOB_PATTERNS[index]);
    assert.equal(rule.headers[0].key.toLowerCase(), globHeader(index));
  });
  assert.equal(
    glob.requests.filter((r) => r.condition === "glob-matching").length,
    GLOB_PATHS.length,
  );
});

test("content types: one file per extension, all sharing one body", () => {
  const routing = corpus.versions[0];
  for (const ext of CONTENT_TYPE_EXTENSIONS) {
    assert.ok(routing.files[`ct/file.${ext}`], ext);
    assert.ok(routing.requests.some((r) => r.id === `v01.ct-${ext}`));
  }
  const bodies = new Set(
    Object.entries(routing.files)
      .filter(([p]) => p.startsWith("ct/"))
      .map(([, b]) => b.toString()),
  );
  assert.equal(bodies.size, 1);
  assert.ok(routing.files["compress/big.txt"].length > 4096);
});

test("the budget the recorder is held to", () => {
  const counts = corpusCounts();
  assert.equal(counts.versions, 10);
  assert.equal(counts.requests, requests.length);
  assert.ok(counts.requests <= 210, "edge requests stay inside the frozen cap");
  assert.ok(counts.distinctBodies <= 16, "uploads stay few");
});
