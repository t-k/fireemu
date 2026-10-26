// Tests of the target table: the FUNCTIONS-HTTP recorder works on named targets (`http`, `callable`)
// and on target specs (another function name, region, codebase), with the named targets behaving
// byte for byte as before.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  expectedFunctionName,
  resolveTarget,
  validateCorpus,
  validateFunctionRecord,
} from "./harness.mjs";
import * as production from "./production.mjs";

const P = "fireemu-oracle-query";
const spec = (extra = {}) => ({
  functionName: "cv14DbCreatedV2",
  region: "us-central1",
  codebase: "rtdb-functions-oracle",
  generation: "gcfv2",
  ...extra,
});

test("the named targets resolve to the FUNCTIONS-HTTP fixture functions", () => {
  assert.deepEqual(resolveTarget("http"), {
    key: "http",
    project: P,
    region: "us-central1",
    codebase: "functions-http-oracle",
    generation: "gcfv2",
    functionName: "fireemuHttpProbe",
    entryPoint: "fireemuHttpProbe",
    runtime: "nodejs22",
  });
  assert.equal(resolveTarget("callable").functionName, "fireemuCallableProbe");
  assert.throws(() => resolveTarget("nope"), /unreviewed target nope/);
  assert.throws(() => resolveTarget(undefined), /unreviewed target/);
  assert.throws(() => resolveTarget("constructor"), /unreviewed target constructor/);
  assert.throws(() => resolveTarget("__proto__"), /unreviewed target/);
});

test("the corpus still accepts only the named targets as strings", () => {
  const corpus = JSON.parse(readFileSync(new URL("./corpus.json", import.meta.url), "utf8"));
  assert.doesNotThrow(() => validateCorpus(corpus));
  corpus.programs[0].cases[0].target = spec();
  assert.throws(() => validateCorpus(corpus), /unreviewed target/);
  assert.throws(() => expectedFunctionName(spec()), /unreviewed target/);
  assert.throws(() => expectedFunctionName("constructor"), /unreviewed target constructor/);
  assert.throws(() => expectedFunctionName(["http"]), /unreviewed target/);
  assert.throws(() => resolveTarget([]), /^Error: invalid target spec$/);
  assert.throws(() => resolveTarget(["http"]), /^Error: invalid target spec$/);
});

test("a target spec gets its own resources, and the named target keeps its old ones", () => {
  const http = production.targetResources("http");
  assert.deepEqual(http, {
    functionUrl: `https://cloudfunctions.googleapis.com/v2/projects/${P}/locations/us-central1/functions/fireemuHttpProbe`,
    serviceName: `projects/${P}/locations/us-central1/services/fireemuhttpprobe`,
    serviceUrl: `https://run.googleapis.com/v2/projects/${P}/locations/us-central1/services/fireemuhttpprobe`,
    packageName: `projects/${P}/locations/us-central1/repositories/gcf-artifacts/packages/fireemu--oracle--query__us--central1__fireemu_http_probe`,
    imagePrefix: `us-central1-docker.pkg.dev/${P}/gcf-artifacts/fireemu--oracle--query__us--central1__fireemu_http_probe`,
    deployArgs: ["deploy", "--only", "functions:functions-http-oracle:fireemuHttpProbe"],
    deleteArgs: ["functions:delete", "fireemuHttpProbe", "--region", "us-central1", "--force"],
  });
  const other = production.targetResources(spec({ region: "europe-west1" }));
  assert.deepEqual(other, {
    functionUrl: `https://cloudfunctions.googleapis.com/v2/projects/${P}/locations/europe-west1/functions/cv14DbCreatedV2`,
    serviceName: `projects/${P}/locations/europe-west1/services/cv14dbcreatedv2`,
    serviceUrl: `https://run.googleapis.com/v2/projects/${P}/locations/europe-west1/services/cv14dbcreatedv2`,
    packageName: `projects/${P}/locations/europe-west1/repositories/gcf-artifacts/packages/fireemu--oracle--query__europe--west1__cv14_db_created_v2`,
    imagePrefix: `europe-west1-docker.pkg.dev/${P}/gcf-artifacts/fireemu--oracle--query__europe--west1__cv14_db_created_v2`,
    deployArgs: ["deploy", "--only", "functions:rtdb-functions-oracle:cv14DbCreatedV2"],
    deleteArgs: ["functions:delete", "cv14DbCreatedV2", "--region", "europe-west1", "--force"],
  });
});

test("a spec that is not a reviewed 2nd gen function of this project is refused", () => {
  const bad = [
    spec({ generation: "gcfv1" }),
    spec({ generation: undefined }),
    spec({ project: "someone-else" }),
    spec({ region: "US-CENTRAL1" }),
    spec({ region: "us-central" }),
    spec({ region: "" }),
    spec({ functionName: "" }),
    spec({ functionName: "has space" }),
    spec({ functionName: "a/b" }),
    spec({ functionName: "x".repeat(64) }),
    // each field is refused by its own rule, so the other fields are valid
    spec({ functionName: "1abc", entryPoint: "entry" }),
    spec({ functionName: 5, entryPoint: "entry" }),
    spec({ functionName: undefined, entryPoint: "entry" }),
    spec({ entryPoint: " abc" }),
    spec({ entryPoint: 7 }),
    spec({ region: "xx us-central1" }),
    spec({ region: "us-central1x" }),
    spec({ region: "us-central1/" }),
    spec({ codebase: "Upper" }),
    spec({ codebase: "a b" }),
    spec({ codebase: "" }),
    spec({ runtime: "" }),
    spec({ entryPoint: "a b" }),
    spec({ unknownField: true }),
    null,
    [],
    5,
  ];
  for (const candidate of bad) {
    assert.throws(
      () => resolveTarget(candidate),
      /unreviewed target|not supported|invalid/,
      JSON.stringify(candidate),
    );
  }
  assert.throws(
    () => resolveTarget(spec({ generation: "gcfv1" })),
    /1st gen targets are not supported/,
  );
  // a spec may name its project, entry point and runtime when they are the reviewed ones
  assert.doesNotThrow(() =>
    resolveTarget(spec({ project: P, runtime: "nodejs22", entryPoint: "other" })),
  );
  const resolved = resolveTarget(spec());
  assert.equal(resolved.key, "cv14DbCreatedV2");
  assert.equal(resolved.entryPoint, "cv14DbCreatedV2");
  assert.equal(resolved.runtime, "nodejs22");
  assert.ok(Object.isFrozen(resolved));
});

test("an image is owned only by the function and region of its target", () => {
  const image = (region, pkg, tail) => `${region}-docker.pkg.dev/${P}/gcf-artifacts/${pkg}${tail}`;
  const digest = `@sha256:${"cd".repeat(32)}`;
  const target = spec({ region: "europe-west1" });
  const pkg = "fireemu--oracle--query__europe--west1__cv14_db_created_v2";
  assert.deepEqual(production.assertOwnedImage(image("europe-west1", pkg, digest), target), {
    packageId: pkg,
    digest: `sha256:${"cd".repeat(32)}`,
    tag: null,
  });
  assert.equal(
    production.assertOwnedImage(image("europe-west1", pkg, ":latest"), target).tag,
    "latest",
  );
  assert.throws(
    () => production.assertOwnedImage(image("us-central1", pkg, digest), target),
    /owned function/,
  );
  assert.throws(
    () =>
      production.assertOwnedImage(
        image("europe-west1", "fireemu--oracle--query__europe--west1__cv14_db_updated_v2", digest),
        target,
      ),
    /owned function/,
  );
  // the named target is unchanged
  assert.equal(
    production.assertOwnedImage(
      image("us-central1", "fireemu--oracle--query__us--central1__fireemu_http_probe", digest),
      "http",
    ).packageId,
    "fireemu--oracle--query__us--central1__fireemu_http_probe",
  );
});

test("a function record is checked against its own target's name, region, entry point and runtime", () => {
  const target = spec({ region: "europe-west1", entryPoint: "entry", runtime: "nodejs20" });
  const record = (patch = {}) => ({
    name: `projects/${P}/locations/europe-west1/functions/cv14DbCreatedV2`,
    environment: "GEN_2",
    buildConfig: { runtime: "nodejs20", entryPoint: "entry" },
    serviceConfig: {
      service: `projects/${P}/locations/europe-west1/services/cv14dbcreatedv2`,
      uri: "https://cv14dbcreatedv2-abc-ew.a.run.app",
    },
    ...patch,
  });
  assert.equal(
    validateFunctionRecord(record(), target),
    "https://cv14dbcreatedv2-abc-ew.a.run.app",
  );
  // the cloudfunctions.net host form belongs to the target's own region and project
  const functionsHost = (host) =>
    record({
      serviceConfig: {
        service: `projects/${P}/locations/europe-west1/services/cv14dbcreatedv2`,
        uri: `https://${host}/cv14DbCreatedV2`,
      },
    });
  assert.equal(
    validateFunctionRecord(functionsHost(`europe-west1-${P}.cloudfunctions.net`), target),
    `https://europe-west1-${P}.cloudfunctions.net/cv14DbCreatedV2`,
  );
  assert.throws(
    () => validateFunctionRecord(functionsHost(`us-central1-${P}.cloudfunctions.net`), target),
    /differs from the reviewed destination/,
  );
  for (const patch of [
    { name: `projects/${P}/locations/us-central1/functions/cv14DbCreatedV2` },
    { buildConfig: { runtime: "nodejs22", entryPoint: "entry" } },
    { buildConfig: { runtime: "nodejs20", entryPoint: "cv14DbCreatedV2" } },
    {
      serviceConfig: {
        service: `projects/${P}/locations/us-central1/services/cv14dbcreatedv2`,
        uri: "https://cv14dbcreatedv2-abc-ew.a.run.app",
      },
    },
    { environment: "GEN_1" },
  ]) {
    assert.throws(
      () => validateFunctionRecord(record(patch), target),
      /differs|not GEN_2/,
      JSON.stringify(patch),
    );
  }
});

test("a deploy and a cleanup of a target spec use its codebase, region, key and resource names", async () => {
  const target = spec({ region: "europe-west1" });
  const keys = [];
  const deployArgs = [];
  const uploads = {
    beginDeploy: async (key) => {
      keys.push(key);
      return { observe() {}, receipt() {}, finish: async () => ({ clean: true, reasons: [] }) };
    },
  };
  const state = { started: false, cleaned: false };
  await production.deployTarget(
    target,
    "program-x",
    state,
    uploads,
    "/adc",
    {},
    "/run",
    async (args, _adc, _budget, kind) => {
      deployArgs.push([args, kind]);
    },
  );
  assert.deepEqual(keys, ["program-x:cv14DbCreatedV2"]);
  assert.deepEqual(deployArgs, [
    [["deploy", "--only", "functions:rtdb-functions-oracle:cv14DbCreatedV2"], "cliDeploy"],
  ]);
  assert.equal(state.started, true);

  // the named target keeps its old key
  const named = [];
  await production.deployTarget(
    "http",
    "program-y",
    { started: false },
    {
      beginDeploy: async (key) => (
        named.push(key),
        { observe() {}, finish: async () => ({ clean: true }) }
      ),
    },
    "/adc",
    {},
    "/run",
    async () => {},
  );
  assert.deepEqual(named, ["program-y:http"]);

  // cleanup: the function is there, then gone; nothing else exists
  const urls = [];
  let present = true;
  const control = async (method, url) => {
    urls.push(`${method} ${url}`);
    if (url.includes("/functions/")) return { status: present ? 200 : 404, value: {} };
    return { status: 404, value: {} };
  };
  const deleted = [];
  const cleanupState = { started: true, cleaned: false };
  await production.cleanupTarget(control, target, "/adc", {}, "/run", cleanupState, {
    run: async (args) => {
      deleted.push(args);
      present = false;
    },
    log: async () => {},
  });
  assert.deepEqual(deleted, [
    ["functions:delete", "cv14DbCreatedV2", "--region", "europe-west1", "--force"],
  ]);
  assert.equal(cleanupState.cleaned, true, cleanupState.cleanupError);
  assert.ok(
    urls.every((u) => u.includes("europe-west1")),
    urls.join("\n"),
  );
  assert.ok(
    urls.some((u) =>
      u.includes("/packages/fireemu--oracle--query__europe--west1__cv14_db_created_v2"),
    ),
  );
});
