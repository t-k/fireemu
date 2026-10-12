import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { checkFixtureDigest, HARNESS_LANES, treeReader } from "../harness-registry.mjs";
import { compareLaneExport } from "../release-strict-regression.mjs";
import grpcLib from "@grpc/grpc-js";
import { protos } from "@google-cloud/pubsub";
import { createBudget } from "../pubsub-production/capture.mjs";
import { createGrpc, SERVICES } from "../pubsub-production/grpc.mjs";
import { createRest } from "../pubsub-production/rest.mjs";
import {
  buildNamesExport,
  compareNamesRows,
  loadNamesFixture,
  main,
  replayNamesProgram,
  validateNamesFixture,
} from "./resource-names.mjs";

const fixture = () =>
  JSON.parse(
    fs.readFileSync(new URL("../../pubsub-resource-names-production.json", import.meta.url)),
  );

test("the fixed subset retains both observations and every admitted name variant", () => {
  const data = fixture();
  assert.doesNotThrow(() => validateNamesFixture(data));
  for (const program of Object.values(data.programs)) {
    assert.equal(program.rows.length, 10);
    for (const transport of ["rest", "grpc"]) {
      assert.deepEqual(
        program.rows.filter((r) => r.transport === transport).map((r) => r.step),
        ["02", "03", "06", "07", "09"],
      );
      const badCharacter = program.rows.find((r) => r.transport === transport && r.step === "07");
      if (transport === "rest") {
        assert.ok(badCharacter.request.path.endsWith("bad%24character-r"));
        assert.equal(badCharacter.response.status, 200);
      } else {
        assert.ok(badCharacter.request.body.name.endsWith("bad$character-g"));
        assert.equal(badCharacter.response.code, "INVALID_ARGUMENT");
      }
    }
  }
});

test("prepared release entry runs both observations on the installed binary under finite exec", () => {
  const run = {
    id: "R21",
    kind: "pubsub-resource-names-comparison-v1",
    clear: ["pubsub-resource-names"],
    commands: [
      ...["O1", "O2"].map((observation) => ({
        mode: "check",
        argv: [
          "{bin}",
          "exec",
          "--config",
          "conformance/src/pubsub-release/fixtures/resource-names.fireemu.json",
          "--project",
          "demo-pubsub-release",
          "--only",
          "pubsub",
          "--pubsub-port",
          "0",
          "--http-port",
          "0",
          "--ui-port",
          "0",
          "--hub-port",
          "0",
          "--logging-port",
          "0",
          "--",
          "node",
          "conformance/src/pubsub-release/resource-names.mjs",
          "check",
          "--bin",
          "{bin}",
          "--observation",
          observation,
        ],
        env: {},
        timeoutMs: 180_000,
        expectedExitCodes: [0, 1],
      })),
      {
        mode: "export-comparison",
        argv: [
          "node",
          "conformance/src/pubsub-release/resource-names.mjs",
          "export-comparison",
          "--bin",
          "{bin}",
          "{export}",
        ],
        env: {},
        timeoutMs: 10_000,
        expectedExitCodes: [0],
      },
    ],
  };
  assert.equal(run.commands.length, 3);
  assert.deepEqual(run.clear, ["pubsub-resource-names"]);
  for (const [i, command] of run.commands.slice(0, 2).entries()) {
    assert.equal(command.mode, "check");
    assert.equal(command.argv[0], "{bin}");
    assert.equal(command.argv[1], "exec");
    assert.equal(command.argv[command.argv.indexOf("--bin") + 1], "{bin}");
    assert.equal(command.argv[command.argv.indexOf("--observation") + 1], ["O1", "O2"][i]);
    assert.equal(command.timeoutMs, 180_000);
    assert.deepEqual(command.expectedExitCodes, [0, 1]);
  }
  assert.equal(run.commands[2].mode, "export-comparison");
  assert.ok(run.commands[2].argv.includes("{export}"));
  assert.equal(
    HARNESS_LANES["pubsub-resource-names"].fixture,
    "pubsub-resource-names-production.json",
  );
  const config = JSON.parse(
    fs.readFileSync(new URL("./fixtures/resource-names.fireemu.json", import.meta.url)),
  );
  assert.equal(config.profile, "strict");
});

test("committed projection has a live harness binding and data drift becomes stale", () => {
  const { data, fixtureSha256 } = loadNamesFixture();
  assert.match(fixtureSha256, /^[a-f0-9]{64}$/);
  const lane = HARNESS_LANES["pubsub-resource-names"];
  const saved = data.programs.O1.harnessDigest;
  assert.equal(checkFixtureDigest("pubsub-resource-names", lane, saved).state, "scheme2");
  assert.equal(
    checkFixtureDigest("pubsub-resource-names", { ...lane, extra: `${lane.extra}changed` }, saved, {
      read: treeReader,
      lineage: [],
    }).state,
    "stale",
  );
});

test("export recomputes exact rows and binds both runs to the installed artifact and fixture", () => {
  const data = fixture();
  const binary = "a".repeat(64),
    fixtureSha256 = "b".repeat(64);
  const records = Object.entries(data.programs).map(([observation, program]) => ({
    observation,
    artifactSha256: binary,
    artifactEndSha256: binary,
    fixtureSha256,
    rows: program.rows.map((r) => ({ row: r.row, response: structuredClone(r.response) })),
    cleanup: { complete: true, uncertain: false },
    requests: 15,
  }));
  const result = buildNamesExport(data, records, binary, fixtureSha256);
  assert.equal(result.rows.length, 20);
  assert.deepEqual(result.summary, { MATCH: 10, DIVERGES: 0, NOT_COMPARABLE: 10 });
  assert.equal(result.artifactSha256, binary);
  const changedBody = structuredClone(result);
  changedBody.rows[0].fireemu.body.error.code = "400";
  assert.equal(changedBody.rows[0].status, "NOT_COMPARABLE");
  assert.ok(compareLaneExport(result, changedBody, binary).length > 0);
  const actualDifference = structuredClone(records);
  actualDifference[0].rows[0].response.body.error.code = "400";
  const differentExport = buildNamesExport(data, actualDifference, binary, fixtureSha256);
  assert.equal(differentExport.rows[0].fireemu.body.error.code, "400");
  assert.equal(differentExport.rows[0].status, "DIVERGES");
  const uncertain = structuredClone(records);
  uncertain[0].cleanup.uncertain = true;
  assert.throws(() => buildNamesExport(data, uncertain, binary, fixtureSha256), /cleanup/);
  const drift = structuredClone(records);
  drift[1].artifactEndSha256 = "c".repeat(64);
  assert.throws(() => buildNamesExport(data, drift, binary, fixtureSha256), /artifact/);
  const stale = structuredClone(records);
  stale[0].fixtureSha256 = "c".repeat(64);
  assert.throws(() => buildNamesExport(data, stale, binary, fixtureSha256), /fixture/);
  assert.throws(
    () => buildNamesExport(data, records.slice(0, 1), binary, fixtureSha256),
    /observations/,
  );
  const debt = structuredClone(records);
  debt[0].cleanup.complete = false;
  assert.throws(() => buildNamesExport(data, debt, binary, fixtureSha256), /cleanup/);
});

test("existing REST and native transports exercise full saved URL, protobuf and response shapes without network", async () => {
  const program = fixture().programs.O1;
  const sources = [...program.setup, ...program.rows];
  const budget = createBudget(24),
    captured = [];
  const capture = {
    record(entry) {
      captured.push(entry);
    },
    note() {},
  };
  let nativeClosed = 0;
  class Client {
    close() {
      nativeClosed++;
    }
    makeUnaryRequest(rpc, encode, decode, body, metadata, options, callback) {
      assert.deepEqual(metadata.getMap(), {});
      assert.ok(options.deadline instanceof Date);
      const [, service, method] = /\/google\.pubsub\.v1\.(\w+)\/(\w+)$/.exec(rpc);
      const [requestType, responseType] = SERVICES[service].methods[method];
      const types = protos.google.pubsub.v1;
      const request = types[requestType].toObject(types[requestType].decode(encode(body)), {
        longs: String,
        enums: String,
        bytes: String,
      });
      assert.deepEqual(request, body);
      if (method.startsWith("Delete"))
        return callback(null, protos.google.protobuf.Empty.fromObject({}));
      const source = sources.find(
        (r) =>
          r.transport === "grpc" &&
          r.request.rpc === `${service}/${method}` &&
          r.request.body.name === request.name,
      );
      assert.ok(source);
      assert.deepEqual(request, source.request.body);
      if (source.response.code !== "OK")
        return callback({ code: 3, details: source.response.message });
      const Response = types[responseType];
      callback(
        null,
        decode(Buffer.from(Response.encode(Response.fromObject(source.response.body)).finish())),
      );
    }
  }
  const native = createGrpc({
    target: "127.0.0.1:19876",
    secure: false,
    budget,
    capture,
    grpc: { ...grpcLib, Client },
  });
  const rest = createRest({
    base: "http://127.0.0.1:19876",
    budget,
    capture,
    async fetchImpl(url, options) {
      assert.equal(options.redirect, "manual");
      assert.equal(options.headers.authorization, undefined);
      const requestPath = url.slice("http://127.0.0.1:19876".length);
      let response = { status: 200, body: {} };
      if (options.method !== "DELETE") {
        const source = sources.find(
          (r) => r.transport === "rest" && r.request.path === requestPath,
        );
        assert.ok(source);
        assert.equal(options.method, source.request.method);
        assert.deepEqual(JSON.parse(options.body), source.request.body);
        response = source.response;
      }
      const bytes = Buffer.from(JSON.stringify(response.body));
      return {
        status: response.status,
        headers: {
          get() {
            return null;
          },
        },
        async arrayBuffer() {
          return bytes;
        },
      };
    },
  });
  let result;
  try {
    result = await replayNamesProgram(program, { rest, grpc: native });
  } finally {
    native.close();
  }
  assert.equal(result.requests, 15);
  assert.equal(captured.length, 15);
  assert.equal(budget.used(), 15);
  assert.equal(result.cleanup.complete, true);
  assert.equal(nativeClosed, 2);
  assert.deepEqual(
    compareNamesRows(program.rows, result.rows).map((r) => r.status),
    program.rows.map((r) => (r.transport === "rest" ? "NOT_COMPARABLE" : "MATCH")),
  );
});

test("real worker entry refuses absent or production endpoints before dispatch", async () => {
  for (const host of [undefined, "pubsub.googleapis.com:443", "127.0.0.1:0", "127.0.0.1:70000"]) {
    await assert.rejects(
      () =>
        main(
          ["check", "--bin", process.execPath, "--observation", "O1"],
          host === undefined ? {} : { PUBSUB_EMULATOR_HOST: host },
        ),
      /loopback/,
    );
  }
});

function transports(program, calls, transform = (response) => response) {
  const sources = [...program.setup, ...program.rows];
  return {
    rest: {
      async request(options) {
        calls.push({ transport: "rest", ...options });
        if (options.method === "DELETE") return { status: 200, body: {} };
        const source = sources.find(
          (r) => r.transport === "rest" && r.request.path === options.path,
        );
        assert.ok(source, "only fixed source requests are admitted");
        assert.equal(options.method, source.request.method);
        assert.deepEqual(options.body, source.request.body);
        return transform(structuredClone(source.response), source);
      },
    },
    grpc: {
      async call(options) {
        calls.push({ transport: "grpc", ...options });
        if (options.method.startsWith("Delete")) return { code: "OK", body: {} };
        const source = sources.find(
          (r) =>
            r.transport === "grpc" &&
            r.request.rpc === `${options.service}/${options.method}` &&
            r.request.body.name === options.request.name,
        );
        assert.ok(source, "only fixed source requests are admitted");
        assert.deepEqual(options.request, source.request.body);
        return transform(structuredClone(source.response), source);
      },
    },
  };
}

test("fixed replay consumes real request shapes and cleans only confirmed owned creations", async () => {
  const program = fixture().programs.O1;
  const calls = [];
  const result = await replayNamesProgram(program, transports(program, calls));
  assert.equal(result.rows.length, 10);
  assert.equal(result.requests, 15);
  assert.equal(result.cleanup.complete, true);
  assert.equal(calls.filter((r) => r.method === "DELETE").length, 2);
  assert.equal(calls.filter((r) => r.method === "DeleteTopic").length, 1);
  assert.ok(result.rows.every((row) => row.response));
});

test("unknown writes stop dispatch and cannot be converted to successful cleanup", async () => {
  const program = fixture().programs.O1;
  const calls = [];
  const result = await replayNamesProgram(
    program,
    transports(program, calls, (response, row) =>
      row.step === "02" ? { status: null, unknown: true } : response,
    ),
  );
  assert.equal(result.requests, 3);
  assert.equal(result.rows.length, 1);
  assert.equal(result.cleanup.complete, false);
  assert.equal(result.cleanup.uncertain, true);
  assert.equal(
    calls.filter((r) => r.method === "DELETE" || r.method.startsWith("Delete")).length,
    0,
  );
});

test("all unexpected successful creations remain bounded and each is deleted once", async () => {
  const program = fixture().programs.O1;
  const calls = [];
  const result = await replayNamesProgram(
    program,
    transports(program, calls, (response, row) =>
      row.transport === "rest"
        ? { status: 200, body: { name: row.request.path.slice(4) } }
        : { code: "OK", body: { name: row.request.body.name } },
    ),
  );
  assert.equal(result.requests, 24);
  assert.equal(result.cleanup.complete, true);
  assert.equal(
    calls.filter((r) => r.method === "DELETE" || r.method.startsWith("Delete")).length,
    12,
  );
  assert.ok(compareNamesRows(program.rows, result.rows).some((row) => row.status === "DIVERGES"));
});

test("subset omissions, duplicate replies and cleanup debt are refused", () => {
  const data = fixture();
  for (const variant of ["observation", "variant", "duplicate"]) {
    const altered = structuredClone(data);
    if (variant === "observation") delete altered.programs.O2;
    if (variant === "variant") altered.programs.O1.rows.pop();
    if (variant === "duplicate")
      altered.programs.O1.rows[1] = structuredClone(altered.programs.O1.rows[0]);
    assert.throws(() => validateNamesFixture(altered));
  }
  const expected = data.programs.O1.rows;
  const actual = expected.map((row) => ({ row: row.row, response: row.response }));
  assert.throws(() => compareNamesRows(expected, [...actual, actual[0]]), /duplicate/);
  assert.throws(() => compareNamesRows(expected, [{ ...actual[0], row: "foreign" }]), /unexpected/);
});

test("the existing strict judge compares every saved status, detail and body", () => {
  const expected = Object.values(fixture().programs).flatMap((p) => p.rows);
  const exact = expected.map((row) => ({ row: row.row, response: structuredClone(row.response) }));
  assert.equal(compareNamesRows(expected, exact).length, 20);
  for (const [i, result] of compareNamesRows(expected, exact).entries()) {
    assert.equal(result.status, expected[i].transport === "rest" ? "NOT_COMPARABLE" : "MATCH");
    if (expected[i].transport === "rest")
      assert.equal(result.reason, "recorded wire length missing");
  }
  for (const change of ["http-status", "http-body", "native-detail", "unknown", "missing"]) {
    const actual = structuredClone(exact);
    const i = change === "native-detail" ? 5 : 0;
    if (change === "http-status") actual[i].response.status = 403;
    if (change === "http-body") actual[i].response.body.error.message = "different detail";
    if (change === "native-detail") actual[i].response.message = "different detail";
    if (change === "unknown") actual[i].response.unknown = true;
    if (change === "missing") actual.splice(i, 1);
    const result = compareNamesRows(expected, actual);
    assert.equal(result.length, 20);
    assert.equal(
      result[i].status,
      ["unknown", "missing"].includes(change) ? "NOT_COMPARABLE" : "DIVERGES",
    );
  }
});
