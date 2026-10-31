// Pure finite value-and-shape evidence over existing session-local output; no transport is started.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createReadStream, readFileSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { projectGrpcMessage, buildRestRequest, buildGrpcRequest } from "./harness.mjs";
import { isMainModule } from "../fs-query-index/main-module.mjs";
const fixtureURL = new URL("../../fixtures/fs-native-positive/production.json", import.meta.url);
const programURL = new URL("../../fixtures/fs-native-positive/program.json", import.meta.url);
const fixtureBytes = readFileSync(fixtureURL),
  programBytes = readFileSync(programURL);
const fixture = JSON.parse(fixtureBytes),
  program = JSON.parse(programBytes)[0];
const recorded = fixture.programs[program.id];
const PREFIX = "projects/demo-fs-query-index/databases/(default)";
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const copy = (x) => structuredClone(x);
export const POLICY = Object.freeze({
  contract: "FINITE_VALUE_AND_SHAPE_ONLY",
  productionRounds: 2,
  localRounds: 2,
  profiles: ["strict", "emulator"],
  transports: ["grpc", "rest"],
  typedFieldsPerRound: 37,
  reference:
    "Complete canonical database prefix with a resource boundary only; no embedded or partial prefix replacement.",
  autogen:
    "Twenty ASCII alphanumeric characters; the two local rounds differ per profile/transport. No entropy, uniqueness or distribution claim.",
  metadata:
    "All production and local message metadata is retained. Identical metadata keys and RFC3339 executionTime type/presence only; no absolute-time equality, clock law, run-window or whole-body parity claim.",
  requestTarget:
    "Raw session files capture resolved bodies only. Path/database are DERIVED from the bound unchanged harness and invocation context, not observed wire paths.",
  absoluteTimeEquality: false,
  parentClosureClaimed: false,
});
/** Replace one complete resource prefix; never rewrite an embedded or partial database name. */
function prefix(value, from, to) {
  if (Array.isArray(value)) return value.map((x) => prefix(x, from, to));
  if (value && typeof value === "object")
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, prefix(v, from, to)]));
  return typeof value === "string" && (value === from || value.startsWith(from + "/"))
    ? to + value.slice(from.length)
    : value;
}
/** Inputs for the existing session-local driver, with only its existing {db} substitution. */
export function programs(transport) {
  assert.ok(["grpc", "rest"].includes(transport), "transport");
  return [
    {
      ...copy(program),
      id: program.id + "-" + transport + "-local",
      steps: program.steps.map((step) => ({
        ...copy(step),
        transport,
        body: prefix(step.body, PREFIX, "{db}"),
      })),
    },
  ];
}
function timestamp(value) {
  assert.equal(typeof value, "string", "executionTime type");
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/.exec(value);
  assert.ok(m, "RFC3339 executionTime");
  const [, y, month, day, hour, minute, second] = m.map(Number);
  assert.ok(
    month >= 1 &&
      month <= 12 &&
      day >= 1 &&
      day <= new Date(Date.UTC(y, month, 0)).getUTCDate() &&
      hour < 24 &&
      minute < 60 &&
      second < 60,
    "executionTime calendar",
  );
}
function metadata(messages) {
  return messages.map((message) =>
    Object.fromEntries(Object.entries(message).filter(([key]) => key !== "results")),
  );
}
function response(raw, transport) {
  assert.equal(raw.transport, transport, "raw transport");
  if (transport === "grpc") {
    assert.equal(raw.response.code, 0, "native status");
    assert.ok(Array.isArray(raw.response.messages), "native messages");
    return raw.response.messages.map((x) => projectGrpcMessage(x));
  }
  assert.equal(raw.response.status, 200, "REST status");
  const body = JSON.parse(raw.response.text);
  assert.ok(Array.isArray(body), "REST response units");
  return body;
}
/** Both typed fields and field presence matter; metadata has its separate explicit policy. */
export function compareReplays(runs, { sourceCommit, binarySha256 }) {
  assert.match(sourceCommit, /^[a-f0-9]{40}$/, "source commit");
  assert.match(binarySha256, /^[a-f0-9]{64}$/, "binary hash");
  assert.equal(runs.length, 8, "eight sessions");
  assert.equal(program.steps.length, 27, "closed positive corpus");
  assert.equal(new Set(program.steps.map((x) => x.id)).size, 27);
  assert.equal(recorded.corpusDigest, digest(JSON.stringify(program)), "captured program binding");
  const seen = new Set(),
    proofs = [],
    localMetadata = [],
    productionMetadata = [],
    autogen = new Map();
  let typedFieldComparisons = 0;
  for (const round of [1, 2])
    for (const step of program.steps) {
      const saved =
        (round === 2 ? recorded.second?.[step.id] : undefined) ?? recorded.steps[step.id];
      productionMetadata.push({ id: step.id, round, messages: copy(metadata(saved.messages)) });
    }
  for (const run of runs) {
    assert.ok(
      ["strict", "emulator"].includes(run.profile) &&
        ["grpc", "rest"].includes(run.transport) &&
        [1, 2].includes(run.round),
      "session axes",
    );
    const key = [run.profile, run.transport, run.round].join("/");
    assert.ok(!seen.has(key), "duplicate session");
    seen.add(key);
    assert.equal(run.sourceCommit, sourceCommit, "single source");
    assert.equal(run.binarySha256, binarySha256, "single binary");
    assert.match(
      run.namespace,
      /^projects\/[A-Za-z0-9_-]+\/databases\/[A-Za-z0-9_()-]+$/,
      "local namespace",
    );
    const invocation = run.invocation;
    assert.equal(invocation.namespace, run.namespace, "producer namespace");
    assert.equal(invocation.sourceCommit, sourceCommit, "producer source");
    assert.equal(invocation.binarySha256, binarySha256, "producer binary");
    for (const [name, hash] of Object.entries(producerInputs(run.transport, run.profile)))
      assert.equal(invocation[name], hash, "producer " + name);
    const origin = new URL(invocation.origin);
    assert.ok(
      origin.protocol === "http:" &&
        ["127.0.0.1", "localhost", "[::1]"].includes(origin.hostname) &&
        origin.pathname === "/" &&
        !origin.username &&
        !origin.password &&
        !origin.search &&
        !origin.hash,
      "loopback producer",
    );
    const resource = /^projects\/([^/]+)\/databases\/([^/]+)$/.exec(run.namespace),
      ctx = {
        project: resource[1],
        database: resource[2],
        target: { kind: "local", origin: origin.origin },
      };
    assert.deepEqual(run.replay.failures, [], "session failures");
    const input = programs(run.transport)[0];
    assert.deepEqual(Object.keys(run.replay.results), [input.id], "one finite program");
    const raw = run.replay.results[input.id].raw;
    assert.deepEqual(
      Object.keys(raw).sort(),
      input.steps.map((x) => x.id).sort(),
      "exact raw cases",
    );
    for (const step of input.steps) {
      const row = raw[step.id],
        saved =
          (run.round === 2 ? recorded.second?.[step.id] : undefined) ?? recorded.steps[step.id];
      assert.equal(saved.transport, "grpc");
      assert.equal(saved.code, 0);
      const request = copy(row.request);
      assert.deepEqual(
        prefix(request, run.namespace, PREFIX),
        prefix(step.body, "{db}", PREFIX),
        "captured request",
      );
      const built =
        run.transport === "grpc"
          ? buildGrpcRequest(step, ctx, new Map())
          : buildRestRequest(step, ctx, new Map());
      if (run.transport === "grpc")
        assert.equal(built.request.database, run.namespace, "derived database");
      else assert.deepEqual(JSON.parse(built.init.body), request, "derived REST body");
      const messages = prefix(response(row, run.transport), run.namespace, PREFIX);
      assert.equal(messages.length, saved.messages.length, "response unit count");
      for (let u = 0; u < messages.length; u++) {
        const actual = messages[u],
          expected = saved.messages[u],
          a = metadata([actual])[0],
          e = metadata([expected])[0];
        assert.deepEqual(Object.keys(a).sort(), Object.keys(e).sort(), "metadata fields");
        assert.deepEqual(Object.keys(e), ["executionTime"], "captured metadata policy");
        timestamp(a.executionTime);
        timestamp(e.executionTime);
        assert.ok(Array.isArray(actual.results), "results array");
        assert.equal(actual.results.length, expected.results.length, "result count");
        for (let r = 0; r < actual.results.length; r++) {
          const got = actual.results[r],
            want = expected.results[r];
          assert.deepEqual(Object.keys(got).sort(), Object.keys(want).sort(), "result fields");
          assert.deepEqual(
            Object.keys(got.fields).sort(),
            Object.keys(want.fields).sort(),
            "complete field set",
          );
          if (step.id === "autogen-document-id") {
            assert.deepEqual(Object.keys(got.fields.value), ["stringValue"], "autogen type");
            const text = got.fields.value.stringValue;
            assert.match(text, /^[A-Za-z0-9]{20}$/, "autogen format");
            const group = run.profile + "/" + run.transport;
            const prior = autogen.get(group) ?? [];
            prior.push(text);
            autogen.set(group, prior);
          } else assert.deepEqual(got.fields, want.fields, "typed values");
          typedFieldComparisons += Object.keys(want.fields).length;
        }
      }
      localMetadata.push({
        profile: run.profile,
        transport: run.transport,
        round: run.round,
        id: step.id,
        messages: copy(metadata(messages)),
      });
      proofs.push({
        profile: run.profile,
        transport: run.transport,
        round: run.round,
        id: step.id,
        productionRound: run.round,
        requestTarget:
          run.transport === "grpc"
            ? {
                classification: "DERIVED_FROM_BOUND_HARNESS_AND_CONTEXT",
                method: built.method,
                database: PREFIX,
              }
            : {
                classification: "DERIVED_FROM_BOUND_HARNESS_AND_CONTEXT",
                method: built.init.method,
                path: "/v1/" + PREFIX + "/documents:executePipeline",
              },
        status: run.transport === "grpc" ? { code: 0 } : { status: 200 },
        results: messages.flatMap((x) => copy(x.results)),
        classification:
          step.id === "autogen-document-id"
            ? "FINITE_ID_FORMAT_AND_TWO_ROUND_DIFFERENCE"
            : "FULL_TYPED_VALUE_AND_FIELDSET_EQUIVALENT",
      });
    }
  }
  for (const values of autogen.values()) {
    assert.equal(values.length, 2, "autogen rounds");
    assert.notEqual(values[0], values[1], "different autogen IDs");
  }
  assert.equal(autogen.size, 4, "autogen profile/transport coverage");
  assert.equal(typedFieldComparisons, 296, "37 fields in eight sessions");
  return {
    kind: "fs-ent-pipeline-native-positive-observation-v1",
    contract: POLICY.contract,
    scope:
      "27 positive shapes and 37 typed fields in two production rounds, compared through both local transports/profiles twice. Value-and-shape only; no clock law, failure behavior, general function domain or parent closure claim.",
    sourceCommit,
    binarySha256,
    policy: copy(POLICY),
    typedFieldComparisons,
    proofs,
    productionMetadata,
    localMetadata,
  };
}
async function boundedJSON(path, limit) {
  const bytes = await readFile(path);
  assert.ok(bytes.length <= limit, "JSON input bound");
  return { bytes, value: JSON.parse(bytes) };
}
async function fileDigest(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}
/** Bind a real installed binary and exact existing-session files; never launch either. */
export async function exportEvidence({ binary, manifest, out }) {
  const entry = await boundedJSON(manifest, 65536),
    m = entry.value,
    binarySha256 = await fileDigest(binary);
  assert.equal(m.binarySha256, binarySha256, "installed binary");
  assert.equal(m.runs.length, 8, "eight files");
  const runs = [],
    localReplaySha256 = [];
  for (const descriptor of m.runs) {
    const captured = await boundedJSON(descriptor.path, 1048576);
    assert.equal(digest(captured.bytes), descriptor.sha256, "local raw hash");
    const receipt = await boundedJSON(descriptor.invocationPath, 65536);
    assert.equal(digest(receipt.bytes), descriptor.invocationSha256, "producer receipt hash");
    runs.push({ ...descriptor, invocation: receipt.value, replay: captured.value });
    localReplaySha256.push({
      profile: descriptor.profile,
      transport: descriptor.transport,
      round: descriptor.round,
      sha256: descriptor.sha256,
      invocationReceiptSha256: descriptor.invocationSha256,
    });
  }
  const result = {
    ...compareReplays(runs, { sourceCommit: m.sourceCommit, binarySha256 }),
    decision: "ACCEPTED_FINITE_VALUE_AND_SHAPE_CONTRACT",
    parentClosureClaimed: false,
    productionJournalSha256: fixture.provenance.productionJournalSha256,
    fixtureSha256: digest(fixtureBytes),
    requestCorpusSha256: digest(programBytes),
    policySha256: digest(JSON.stringify(POLICY)),
    manifestSha256: digest(entry.bytes),
    localReplaySha256,
  };
  await writeFile(out, JSON.stringify(result, null, 2) + "\n", { flag: "wx" });
  return result;
}
if (isMainModule(import.meta)) {
  const [mode, ...args] = process.argv.slice(2);
  try {
    if (mode === "programs" && args.length === 2)
      await writeFile(args[1], JSON.stringify(programs(args[0]), null, 2) + "\n", { flag: "wx" });
    else if (mode === "export-comparison" && args.length === 6) {
      const options = {};
      for (let i = 0; i < args.length; i += 2) {
        assert.ok(
          ["--binary", "--manifest", "--out"].includes(args[i]) &&
            !Object.hasOwn(options, args[i].slice(2)),
          "CLI option",
        );
        options[args[i].slice(2)] = args[i + 1];
      }
      assert.equal(Object.keys(options).length, 3);
      await exportEvidence(options);
    } else
      throw Error(
        "usage: native-positive.mjs programs grpc|rest out.json OR export-comparison --binary path --manifest manifest.json --out evidence.json",
      );
  } catch (error) {
    process.stderr.write(String(error.message) + "\n");
    process.exitCode = 1;
  }
}

/** Exact inputs for a Root-owned invocation receipt; not a capture of a wire target. */
export function producerInputs(transport, profile) {
  assert.ok(["strict", "emulator"].includes(profile));
  return {
    inputSha256: digest(JSON.stringify(programs(transport), null, 2) + "\n"),
    seedSha256: digest(JSON.stringify(program.seed)),
    configSha256: digest(
      readFileSync(
        new URL(
          profile === "strict"
            ? "../../fs-ent-pipeline.fireemu.json"
            : "../../fs-ent-pipeline.emulator.fireemu.json",
          import.meta.url,
        ),
      ),
    ),
    harnessSha256: digest(readFileSync(new URL("./harness.mjs", import.meta.url))),
    sessionSha256: digest(readFileSync(new URL("./session.mjs", import.meta.url))),
    driverSha256: digest(readFileSync(new URL("../fs-query-index/run.mjs", import.meta.url))),
  };
}
