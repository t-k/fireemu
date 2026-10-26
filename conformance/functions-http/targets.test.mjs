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
    resourceId: "us-central1/fireemuHttpProbe",
    named: true,
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
    // a spec has no CLI delete: `functions:delete <name>` can reach a codebase or every `<name>-*`
    deleteArgs: null,
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

const OPERATION = `projects/${P}/locations/europe-west1/operations/op-1`;

/** A control for one europe-west1 function that is deployed, then deleted through its exact resource. */
function worldFor(
  target,
  { operation = { name: OPERATION, done: true }, deleteAnswer, siblings = [] } = {},
) {
  const calls = [];
  let present = true;
  const control = async (method, url, body, kind, allowed = [200]) => {
    calls.push({ method, url, kind });
    const answer = await respond(method, url);
    if (!allowed.includes(answer.status)) throw new Error(`status ${answer.status}`);
    return answer;
  };
  const respond = async (method, url) => {
    if (method === "DELETE" && url.endsWith(`/functions/${target.functionName}`)) {
      if (deleteAnswer) return deleteAnswer();
      present = false;
      return { status: 200, value: operation };
    }
    if (method === "GET" && url.endsWith(`/operations/op-1`)) {
      return { status: 200, value: { name: OPERATION, done: true } };
    }
    if (url.includes("/functions?")) {
      return { status: 200, value: { functions: siblings } };
    }
    if (url.includes("/repositories/gcf-artifacts/packages?")) {
      return { status: 200, value: { packages: [] } };
    }
    if (url.includes("/functions/")) {
      return present ? { status: 200, value: {} } : { status: 404, value: {} };
    }
    return { status: 404, value: {} };
  };
  return { control, calls, present: () => present };
}

const fakeUploads = (region) => ({
  region,
  beginDeploy: async () => ({ observe() {}, receipt() {}, finish: async () => ({ clean: true }) }),
});

test("a deploy of a spec uses its codebase, key and region, and refuses another region before anything starts", async () => {
  const target = spec({ region: "europe-west1" });
  const deployArgs = [];
  const keys = [];
  const uploads = {
    region: "europe-west1",
    beginDeploy: async (key) => {
      keys.push(key);
      return { observe() {}, receipt() {}, finish: async () => ({ clean: true }) };
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
    async (args, _a, _b, kind) => {
      deployArgs.push([args, kind]);
    },
  );
  assert.deepEqual(keys, ["program-x:cv14DbCreatedV2"]);
  assert.deepEqual(deployArgs, [
    [["deploy", "--only", "functions:rtdb-functions-oracle:cv14DbCreatedV2"], "cliDeploy"],
  ]);
  assert.equal(state.started, true);
  assert.equal(state.target.functionName, "cv14DbCreatedV2");
  assert.ok(Object.isFrozen(state.target));

  // a helper of another region (the uploads bucket is per region): nothing is started, no CLI is spawned
  const ran = [];
  const begun = [];
  const wrong = { region: "us-central1", beginDeploy: async (key) => begun.push(key) };
  const fresh = { started: false };
  await assert.rejects(
    () =>
      production.deployTarget(target, "program-x", fresh, wrong, "/adc", {}, "/run", async () =>
        ran.push(1),
      ),
    /target region differs from the region of the upload helper/,
  );
  assert.deepEqual([ran, begun, fresh], [[], [], { started: false }]);
  // a helper without a region is refused as well
  await assert.rejects(
    () =>
      production.deployTarget(
        target,
        "p",
        { started: false },
        { beginDeploy: async () => {} },
        "/adc",
        {},
        "/run",
        async () => {},
      ),
    /differs from the region/,
  );
  // the named target keeps its old key and region
  const named = [];
  await production.deployTarget(
    "http",
    "program-y",
    { started: false },
    {
      region: "us-central1",
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
});

test("a spec is deleted by its exact resource, once, never by a selector (M1)", async () => {
  const target = spec({ region: "europe-west1" });
  const { control, calls } = worldFor(target);
  const state = { started: true, cleaned: false, target: resolveTarget(target) };
  const ran = [];
  await production.cleanupTarget(control, target, "/adc", {}, "/run", state, {
    run: async (args) => ran.push(args),
    log: async () => {},
    sleep: async () => {},
  });
  assert.deepEqual(ran, [], "no CLI delete for a spec");
  assert.equal(state.cleaned, true, state.cleanupError);
  const deletes = calls.filter((c) => c.method === "DELETE");
  assert.deepEqual(
    deletes.map((c) => c.url),
    [
      `https://cloudfunctions.googleapis.com/v2/projects/${P}/locations/europe-west1/functions/cv14DbCreatedV2`,
    ],
  );
  assert.ok(calls.every((c) => c.url.includes("europe-west1")));
  // the function and the service were read back
  assert.ok(
    calls.filter((c) => c.method === "GET" && c.url.includes("/functions/cv14DbCreatedV2"))
      .length >= 2,
  );
  assert.ok(calls.some((c) => c.url.includes("/services/cv14dbcreatedv2")));
});

test("the exact delete is sent once; an unknown answer, a refusal or a bad operation leaves the target residual", async () => {
  const target = spec({ region: "europe-west1" });
  const cases = [
    [
      "a thrown request",
      {
        deleteAnswer: () => {
          throw new Error("reset");
        },
      },
      /reset/,
    ],
    ["a 503", { deleteAnswer: () => ({ status: 503, value: {} }) }, /returned 503|status 503/],
    [
      "an operation of another project",
      { operation: { name: "projects/other/locations/europe-west1/operations/o", done: true } },
      /unreviewed delete operation/,
    ],
    ["no operation name", { operation: { done: true } }, /unreviewed delete operation/],
    [
      "an operation of another region",
      { operation: { name: `projects/${P}/locations/us-central1/operations/op-1`, done: true } },
      /unreviewed delete operation/,
    ],
    [
      "an operation name with a path",
      { operation: { name: `${OPERATION}/../../x`, done: true } },
      /unreviewed delete operation/,
    ],
    [
      "an operation with an error",
      { operation: { name: OPERATION, done: true, error: { code: 9 } } },
      /delete operation failed/,
    ],
    [
      "an operation that never finishes",
      { operation: { name: OPERATION, done: false } },
      /did not complete within 10 polls/,
    ],
  ];
  for (const [label, options, pattern] of cases) {
    const world = worldFor(target, options);
    if (options.operation && !options.operation.done) {
      const inner = world.control;
      world.control = async (method, url, body, kind, allowed) =>
        method === "GET" && url.endsWith("/operations/op-1")
          ? { status: 200, value: { name: OPERATION, done: false } }
          : inner(method, url, body, kind, allowed);
    }
    const state = { started: true, cleaned: false, target: resolveTarget(target) };
    let slept = 0;
    await production.cleanupTarget(world.control, target, "/adc", {}, "/run", state, {
      run: async () => {
        throw new Error("no CLI");
      },
      log: async () => {},
      sleep: async () => {
        slept += 1;
      },
    });
    assert.equal(state.cleaned, false, label);
    assert.match(state.cleanupError, pattern, label);
    assert.equal(world.calls.filter((c) => c.method === "DELETE").length, 1, `${label}: sent once`);
    if (label === "an operation that never finishes") assert.equal(slept, 10);
  }
});

test("a spec is cleaned as it was deployed, even when the caller's object changed afterwards (S1)", async () => {
  const raw = spec({ region: "europe-west1" });
  const uploads = fakeUploads("europe-west1");
  const state = { started: false, cleaned: false };
  await production.deployTarget(
    raw,
    "program-x",
    state,
    uploads,
    "/adc",
    {},
    "/run",
    async () => {},
  );
  raw.functionName = "somethingElse";
  raw.region = "us-central1";
  const world = worldFor(resolveTarget(state.target));
  await production.cleanupTarget(world.control, raw, "/adc", {}, "/run", state, {
    log: async () => {},
    sleep: async () => {},
  });
  assert.equal(state.cleaned, true, state.cleanupError);
  const deletes = world.calls.filter((c) => c.method === "DELETE").map((c) => c.url);
  assert.deepEqual(deletes, [
    `https://cloudfunctions.googleapis.com/v2/projects/${P}/locations/europe-west1/functions/cv14DbCreatedV2`,
  ]);
});

test("only plain objects with own data fields are specs, and a resolved spec resolves to itself (S1)", () => {
  const inherited = Object.create(spec());
  const withGetter = { ...spec() };
  Object.defineProperty(withGetter, "functionName", { get: () => "aaa", enumerable: true });
  const hidden = Object.defineProperty({ ...spec() }, "region", {
    value: "us-central1",
    enumerable: false,
  });
  const nullProto = Object.assign(Object.create(null), spec());
  class Spec {
    constructor() {
      Object.assign(this, spec());
    }
  }
  const withSymbol = { ...spec(), [Symbol("x")]: 1 };
  for (const candidate of [inherited, withGetter, nullProto, new Spec(), withSymbol]) {
    assert.throws(() => resolveTarget(candidate), /invalid target spec/);
  }
  assert.doesNotThrow(
    () => resolveTarget(hidden),
    "a non-enumerable own data field is still an own data field",
  );
  const resolved = resolveTarget(spec());
  assert.equal(resolveTarget(resolved), resolved);
  const named = resolveTarget("http");
  assert.equal(resolveTarget(named), named);
  // a frozen result is not a spec the caller could have forged
  assert.throws(() => resolveTarget({ ...resolved }), /unknown field (key|resourceId|named)/);
  // a mutable raw object is read once per resolve: later changes do not touch the result
  const raw = spec();
  const once = resolveTarget(raw);
  raw.functionName = "changed";
  assert.equal(once.functionName, "cv14DbCreatedV2");
});

test("a spec cannot be named like a codebase, and cannot sit beside functions of a similar name (M1)", async () => {
  for (const name of ["default", "functions-http-oracle", "rtdb-functions-oracle"]) {
    assert.throws(
      () => resolveTarget(spec({ functionName: name })),
      /functionName equals a codebase name/,
      name,
    );
  }
  assert.throws(
    () => resolveTarget(spec({ functionName: "same-name", codebase: "same-name" })),
    /equals a codebase name/,
  );
  const target = spec({ functionName: "fireemuHttpProbe-x" });
  assert.equal(resolveTarget(target).functionName, "fireemuHttpProbe-x");
  const listOf = (functions) => async (_m, url) =>
    url.includes("/functions?")
      ? { status: 200, value: { functions } }
      : { status: 404, value: {} };
  const fn = (id, codebase) => ({
    name: `projects/${P}/locations/us-central1/functions/${id}`,
    labels: codebase ? { "deployment-codebase": codebase } : {},
  });
  // nothing similar: accepted
  await assert.doesNotReject(() => production.assertTargetAbsent(listOf([fn("other")]), target));
  // a sibling that starts with `<name>-`, and an exact name in the list
  await assert.rejects(
    () => production.assertTargetAbsent(listOf([fn("fireemuHttpProbe-x-y")]), target),
    /collides with the function fireemuHttpProbe-x-y/,
  );
  await assert.rejects(
    () => production.assertNoNameCollisions(listOf([fn("fireemuHttpProbe-x")]), target),
    /collides/,
  );
  // a function deployed from a codebase named like the target
  await assert.rejects(
    () => production.assertTargetAbsent(listOf([fn("other", "fireemuHttpProbe-x")]), target),
    /equals the codebase of the function other/,
  );
  // `fireemuHttpProbe-xy` does not start with `fireemuHttpProbe-x-`: not a sibling
  await assert.doesNotReject(() =>
    production.assertNoNameCollisions(listOf([fn("fireemuHttpProbe-xy")]), target),
  );
});

test("the function list of a region must be complete, and the named targets are not listed at all", async () => {
  const target = spec();
  let pages = 0;
  const endless = async (_m, url) => {
    if (!url.includes("/functions?")) return { status: 404, value: {} };
    pages += 1;
    return { status: 200, value: { functions: [], nextPageToken: `t${pages}` } };
  };
  await assert.rejects(() => production.assertNoNameCollisions(endless, target), /incomplete/);
  assert.equal(pages, 5);
  const urls = [];
  await production.assertTargetAbsent(
    async (_m, url) => (urls.push(url), { status: 404, value: {} }),
    "http",
  );
  assert.ok(
    urls.every((u) => !u.includes("/functions?")),
    "the named target reads exactly what it read before",
  );
  // the listing of pages follows the token
  const seen = [];
  const paged = async (_m, url) => {
    if (!url.includes("/functions?")) return { status: 404, value: {} };
    seen.push(url);
    return url.includes("pageToken=p2")
      ? { status: 200, value: { functions: [] } }
      : { status: 200, value: { functions: [], nextPageToken: "p2" } };
  };
  await production.assertNoNameCollisions(paged, target);
  assert.equal(seen.length, 2);
});

test("the programs of a corpus key their states by the canonical target, and a function is named once (S2)", () => {
  const program = (...targets) => ({ cases: targets.map((target) => ({ target })) });
  const a = spec({ functionName: "cv14A" });
  const b = spec({ functionName: "cv14B" });
  assert.deepEqual(
    production.programTargets(program("http", "callable", "http")).map((t) => t.key),
    ["http", "callable"],
  );
  assert.deepEqual(
    production.programTargets(program(a, b, a)).map((t) => t.key),
    ["cv14A", "cv14B"],
  );
  assert.deepEqual(
    production.programTargets(program(a, { ...a })).map((t) => t.key),
    ["cv14A"],
  );
  // the same function through a name and a spec, or two keys for one resource
  assert.throws(
    () =>
      production.programTargets(
        program("http", {
          functionName: "fireemuHttpProbe",
          region: "us-central1",
          codebase: "functions-http-oracle",
          generation: "gcfv2",
        }),
      ),
    /name the same function us-central1\/fireemuHttpProbe/,
  );
  assert.throws(
    () =>
      production.programTargets(
        program(a, spec({ functionName: "cv14A", region: "europe-west1" })),
      ),
    /share the key cv14A/,
  );
  assert.throws(() => production.programTargets(program("nope")), /unreviewed target nope/);
});

test("the preflight checks the Artifact Registry repository of the region it is given", async () => {
  const seen = [];
  const control = async (_m, url) => {
    seen.push(url);
    if (url.includes("serviceusage")) {
      return {
        status: 200,
        value: {
          services: [
            "cloudfunctions",
            "cloudbuild",
            "artifactregistry",
            "run",
            "eventarc",
            "pubsub",
            "storage",
            "firebaseextensions",
          ].map((name) => ({ config: { name: `${name}.googleapis.com` } })),
        },
      };
    }
    if (url.includes("/repositories/")) {
      const region = url.split("/locations/")[1].split("/")[0];
      return {
        status: 200,
        value: {
          name: `projects/${P}/locations/${region}/repositories/gcf-artifacts`,
          format: "DOCKER",
          mode: "STANDARD_REPOSITORY",
          cleanupPolicies: {
            "firebase-functions-cleanup": {
              id: "firebase-functions-cleanup",
              action: "DELETE",
              condition: { tagState: "ANY", olderThan: "86400s" },
            },
          },
        },
      };
    }
    return { status: 200, value: { projectId: P } };
  };
  await production.preflightCliSideEffects(control, "europe-west1");
  assert.ok(seen.some((u) => u.endsWith("/locations/europe-west1/repositories/gcf-artifacts")));
  seen.length = 0;
  await production.preflightCliSideEffects(control);
  assert.ok(seen.some((u) => u.endsWith("/locations/us-central1/repositories/gcf-artifacts")));
  // a repository that answers with another region's name is refused
  await assert.rejects(
    () =>
      production.preflightCliSideEffects(
        async (m, u) =>
          u.includes("/repositories/")
            ? {
                status: 200,
                value: { name: `projects/${P}/locations/us-central1/repositories/gcf-artifacts` },
              }
            : control(m, u),
        "europe-west1",
      ),
    /gcf-artifacts repository is absent/,
  );
});

test("the named targets keep their literal CLI arguments and resource names (golden)", () => {
  assert.deepEqual(production.targetResources("callable"), {
    functionUrl: `https://cloudfunctions.googleapis.com/v2/projects/${P}/locations/us-central1/functions/fireemuCallableProbe`,
    serviceName: `projects/${P}/locations/us-central1/services/fireemucallableprobe`,
    serviceUrl: `https://run.googleapis.com/v2/projects/${P}/locations/us-central1/services/fireemucallableprobe`,
    packageName: `projects/${P}/locations/us-central1/repositories/gcf-artifacts/packages/fireemu--oracle--query__us--central1__fireemu_callable_probe`,
    imagePrefix: `us-central1-docker.pkg.dev/${P}/gcf-artifacts/fireemu--oracle--query__us--central1__fireemu_callable_probe`,
    deployArgs: ["deploy", "--only", "functions:functions-http-oracle:fireemuCallableProbe"],
    deleteArgs: ["functions:delete", "fireemuCallableProbe", "--region", "us-central1", "--force"],
  });
});

test("the exact delete is counted in the cleanup budget, and a missing function is not deleted again", async () => {
  const target = spec({ region: "europe-west1" });
  const world = worldFor(target);
  const state = { started: true, cleaned: false, target: resolveTarget(target) };
  await production.cleanupTarget(world.control, target, "/adc", {}, "/run", state, {
    log: async () => {},
    sleep: async () => {},
  });
  assert.ok(world.calls.filter((c) => c.method === "DELETE").every((c) => c.kind === "cleanup"));
  assert.ok(
    world.calls.filter((c) => c.url.includes("/operations/")).every((c) => c.kind === "cleanup"),
  );

  // the function is gone but its service is not: no function DELETE is sent, the run is residual
  const calls = [];
  const control = async (method, url, _b, _kind, allowed = [200]) => {
    calls.push({ method, url });
    const answer = url.includes("/services/")
      ? { status: 200, value: {} }
      : { status: 404, value: {} };
    if (!allowed.includes(answer.status)) throw new Error(`status ${answer.status}`);
    return answer;
  };
  const residual = { started: true, cleaned: false, target: resolveTarget(target) };
  await production.cleanupTarget(control, target, "/adc", {}, "/run", residual, {
    log: async () => {},
    sleep: async () => {},
  });
  assert.equal(residual.cleaned, false);
  assert.match(residual.cleanupError, /Cloud Run service remains after delete/);
  assert.equal(calls.filter((c) => c.method === "DELETE").length, 0);
});

test("the image residue check follows the target's region and package names (after the merge with the probe follow-ups)", async () => {
  const target = spec({ region: "europe-west1" });
  const pkg = `projects/${P}/locations/europe-west1/repositories/gcf-artifacts/packages/fireemu--oracle--query__europe--west1__cv14_db_created_v2`;
  const seen = [];
  const control = async (_m, url) => {
    seen.push(url);
    if (url.endsWith("/europe-west1/repositories/gcf-artifacts/packages?pageSize=1000")) {
      return {
        status: 200,
        value: { packages: [{ name: `${pkg}%2Fcache` }, { name: `${pkg}-other` }] },
      };
    }
    return { status: 200, value: { versions: [{ name: `${pkg}%2Fcache/versions/sha256:x` }] } };
  };
  await assert.rejects(
    () => production.assertNoImageResidue(control, target, "cleanup"),
    /owned image version remains in fireemu--oracle--query__europe--west1__cv14_db_created_v2%2Fcache/,
  );
  assert.ok(seen[0].includes("/locations/europe-west1/repositories/gcf-artifacts/packages?"));
  assert.ok(seen[1].includes(`${pkg}%2Fcache/versions`));
  assert.equal(seen.length, 2, "the package with a longer id is not ours and is not read");
});
