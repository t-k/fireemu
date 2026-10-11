import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { checkFixtureDigest, HARNESS_LANES } from "../harness-registry.mjs";
import { createBudget } from "../pubsub-production/capture.mjs";
import { createRest } from "../pubsub-production/rest.mjs";
import { createGrpc } from "../pubsub-production/grpc.mjs";
import { judgeRow } from "../pubsub-production/stream-dlq-compare-core.mjs";

const steps = ["02", "03", "06", "07", "09"];
const variants = [
  "reserved-topic",
  "too-short",
  "leading-digit",
  "invalid-character",
  "reserved-subscription",
];
const project = "demo-pubsub-release";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const fixturePath = path.join(root, "conformance/pubsub-resource-names-production.json");
const runDirectory = path.join(root, "conformance/.runs/pubsub-resource-names");
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function loadNamesFixture() {
  const bytes = fs.readFileSync(fixturePath);
  const data = validateNamesFixture(JSON.parse(bytes));
  for (const program of Object.values(data.programs)) {
    const binding = checkFixtureDigest(
      "pubsub-resource-names",
      HARNESS_LANES["pubsub-resource-names"],
      program.harnessDigest,
    );
    if (binding.state === "stale") throw new Error("STALE_FIXTURE");
  }
  return { data, fixtureSha256: sha(bytes) };
}

export function validateNamesFixture(data) {
  if (
    data?.project !== project ||
    data.scope !== "SUPPLEMENTARY_ON_RELEASE_BINARY" ||
    JSON.stringify(Object.keys(data.programs ?? {}).sort()) !== '["O1","O2"]'
  ) {
    throw new Error("fixed name subset required");
  }
  for (const [alias, program] of Object.entries(data.programs)) {
    if (program.rows?.length !== 10 || program.setup?.length !== 2)
      throw new Error("incomplete name witnesses");
    for (const transport of ["rest", "grpc"]) {
      const selected = program.rows.filter((row) => row.transport === transport);
      if (JSON.stringify(selected.map((row) => row.step)) !== JSON.stringify(steps))
        throw new Error("incomplete name variants");
      for (const [i, row] of selected.entries()) {
        const caseId = ["02", "09"].includes(row.step) ? "reserved-prefix" : "invalid-name";
        if (
          row.row !== `pubsub/resource-names/${alias}/${transport}/${caseId}/${variants[i]}` ||
          row.caseId !== caseId ||
          row.variant !== variants[i] ||
          row.case !== `names/${transport}` ||
          row.coordinate !== `/conditions/1/cases/${caseId === "reserved-prefix" ? 3 : 1}`
        ) {
          throw new Error("name witness identity mismatch");
        }
      }
    }
  }
  return data;
}

export function compareNamesRows(expected, actual) {
  const seen = new Set();
  for (const row of actual) {
    if (seen.has(row.row) || !expected.some((e) => e.row === row.row))
      throw new Error("unexpected or duplicate local row");
    seen.add(row.row);
  }
  return expected.map((row) => {
    const observed = actual.find((r) => r.row === row.row);
    const judgment = judgeRow(row, observed);
    return {
      row: row.row,
      status: judgment.verdict,
      reason: judgment.reason,
      coordinate: row.coordinate,
      production: row.response,
      fireemu: observed?.response ?? null,
    };
  });
}

export async function replayNamesProgram(program, { rest, grpc }) {
  const rows = [];
  const owned = [];
  let requests = 0;
  let uncertain = false;
  let cleanupComplete = true;
  const send = async (row) => {
    if (++requests > 24) throw new Error("fixed local request bound exceeded");
    let response;
    if (row.transport === "rest") {
      response = await rest.request({
        label: { case: row.case, step: row.step },
        op: row.op,
        ...row.request,
        timeoutMs: 5000,
      });
    } else {
      const [service, method] = row.request.rpc.split("/");
      response = await grpc.call({
        label: { case: row.case, step: row.step },
        op: row.op,
        service,
        method,
        request: row.request.body,
        timeoutMs: 5000,
      });
    }
    if (response.unknown === true) uncertain = true;
    return { row: row.row, response };
  };
  const successful = (row, actual) =>
    row.transport === "rest"
      ? actual.response.status >= 200 && actual.response.status < 300
      : actual.response.code === "OK";
  const track = (row, actual) => {
    if (!successful(row, actual)) return;
    const name = row.transport === "rest" ? row.request.path.slice(4) : row.request.body.name;
    if (actual.response.body?.name !== name) {
      uncertain = true;
      return;
    }
    owned.push({
      name,
      transport: row.transport,
      kind: row.op === "createTopic" ? "Topic" : "Subscription",
    });
  };
  try {
    for (const row of program.setup) {
      const actual = await send(row);
      track(row, actual);
      if (uncertain || !successful(row, actual)) throw new Error("owned setup not confirmed");
    }
    for (const row of program.rows) {
      const actual = await send(row);
      rows.push(actual);
      track(row, actual);
      if (uncertain) break;
    }
  } catch {
    uncertain = true;
  } finally {
    if (uncertain) cleanupComplete = false;
    else
      for (const resource of owned.toReversed()) {
        const row = {
          transport: resource.transport,
          case: `cleanup/${resource.transport}`,
          step: "delete",
          op: `delete${resource.kind}`,
          request:
            resource.transport === "rest"
              ? { method: "DELETE", path: `/v1/${resource.name}` }
              : {
                  rpc: `${resource.kind === "Topic" ? "Publisher" : "Subscriber"}/Delete${resource.kind}`,
                  body: { [resource.kind === "Topic" ? "topic" : "subscription"]: resource.name },
                },
        };
        try {
          const actual = await send(row);
          if (uncertain || !successful(row, actual)) {
            cleanupComplete = false;
            break;
          }
        } catch {
          cleanupComplete = false;
          break;
        }
      }
  }
  return { rows, requests, cleanup: { complete: cleanupComplete, uncertain } };
}

export function buildNamesExport(data, records, binarySha256, fixtureSha256) {
  validateNamesFixture(data);
  if (
    records.length !== 2 ||
    new Set(records.map((r) => r.observation)).size !== 2 ||
    !records.every((r) => ["O1", "O2"].includes(r.observation))
  )
    throw new Error("both observations required");
  const rows = [];
  for (const observation of ["O1", "O2"]) {
    const record = records.find((r) => r.observation === observation);
    if (record.artifactSha256 !== binarySha256 || record.artifactEndSha256 !== binarySha256)
      throw new Error("installed artifact changed");
    if (record.fixtureSha256 !== fixtureSha256) throw new Error("fixture changed");
    if (
      !record.cleanup?.complete ||
      record.cleanup.uncertain ||
      record.rows.length !== 10 ||
      !Number.isInteger(record.requests) ||
      record.requests < 12 ||
      record.requests > 24
    )
      throw new Error("incomplete local replay or cleanup");
    rows.push(...compareNamesRows(data.programs[observation].rows, record.rows));
  }
  const summary = { MATCH: 0, DIVERGES: 0, NOT_COMPARABLE: 0 };
  for (const row of rows) summary[row.status]++;
  return {
    kind: "pubsub-resource-names-comparison-v1",
    fixtureSha256,
    artifactSha256: binarySha256,
    scope: data.scope,
    summary,
    rows,
  };
}

export async function main(args = process.argv.slice(2), environment = process.env) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { bin: { type: "string" }, observation: { type: "string" } },
  });
  const mode = positionals[0];
  if (!values.bin || !path.isAbsolute(values.bin))
    throw new Error("absolute installed binary required");
  if (mode === "check") {
    const host = environment.PUBSUB_EMULATOR_HOST;
    if (!/^127\.0\.0\.1:[1-9]\d{0,4}$/.test(host ?? "") || Number(host.split(":")[1]) > 65535)
      throw new Error("loopback Pub/Sub endpoint required");
    if (!["O1", "O2"].includes(values.observation) || positionals.length !== 1)
      throw new Error("fixed observation required");
    const { data, fixtureSha256 } = loadNamesFixture();
    const artifactSha256 = sha(fs.readFileSync(values.bin));
    const budget = createBudget(24);
    const capture = { record() {}, note() {} };
    const native = createGrpc({
      target: host,
      secure: false,
      budget,
      capture,
      defaultTimeoutMs: 5000,
    });
    const rest = createRest({ base: `http://${host}`, budget, capture, defaultTimeoutMs: 5000 });
    let result;
    try {
      result = await replayNamesProgram(data.programs[values.observation], { rest, grpc: native });
    } finally {
      native.close();
    }
    const artifactEndSha256 = sha(fs.readFileSync(values.bin));
    const report = {
      observation: values.observation,
      artifactSha256,
      artifactEndSha256,
      fixtureSha256,
      ...result,
    };
    fs.mkdirSync(runDirectory, { recursive: true });
    fs.writeFileSync(
      path.join(runDirectory, `${values.observation}.json`),
      `${JSON.stringify(report, null, 2)}\n`,
      { flag: "wx" },
    );
    const rows = compareNamesRows(data.programs[values.observation].rows, result.rows);
    const refused =
      !result.cleanup.complete ||
      result.cleanup.uncertain ||
      result.rows.length !== 10 ||
      artifactSha256 !== artifactEndSha256 ||
      rows.some(
        (r) => r.status === "NOT_COMPARABLE" && r.reason !== "recorded wire length missing",
      );
    console.log(
      JSON.stringify({
        observation: values.observation,
        requests: result.requests,
        cleanup: result.cleanup,
      }),
    );
    return refused ? 2 : rows.some((r) => r.status === "DIVERGES") ? 1 : 0;
  }
  if (mode !== "export-comparison" || positionals.length !== 2 || values.observation)
    throw new Error("check or export-comparison required");
  const { data, fixtureSha256 } = loadNamesFixture();
  const records = ["O1", "O2"].map((id) =>
    JSON.parse(fs.readFileSync(path.join(runDirectory, `${id}.json`))),
  );
  const exported = buildNamesExport(data, records, sha(fs.readFileSync(values.bin)), fixtureSha256);
  fs.writeFileSync(positionals[1], `${JSON.stringify(exported, null, 2)}\n`, { flag: "wx" });
  console.log(
    JSON.stringify({ summary: exported.summary, artifactSha256: exported.artifactSha256 }),
  );
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      console.error(error.message);
      process.exitCode = 2;
    });
}
