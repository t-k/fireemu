// Offline replay of recorded direct REST server values; no production access.
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { createHash, randomBytes } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const RAW_SHA = "3411fb9ff5220a7e3bb680f0674ea2a9242a3abe9f2ae989683d0e1f13e3a92c";
const IDS = [
  "timestamp-single",
  "increment-numeric",
  "increment-absent",
  "increment-nonnumeric",
  "multipath-one-clock",
];
const TOKEN = "<timestamp>";
const integer = (value) => Number.isSafeInteger(value);
const parsed = (text) => {
  try {
    return JSON.parse(text);
  } catch {
    throw Error("invalid JSON response");
  }
};
function validShape(row) {
  if (
    !IDS.includes(row?.id) ||
    !["r1", "r2"].includes(row?.round) ||
    ![row.before?.status, row.response?.status, row.after?.status].every((x) => x === 200) ||
    typeof row.request?.body !== "string" ||
    !["PUT", "PATCH"].includes(row.request?.method)
  )
    throw Error("invalid observation");
}
export function maskObservation(row) {
  validShape(row);
  if (!isDeepStrictEqual(row.value, row.readback)) throw Error("write/readback mismatch");
  let value = structuredClone(row.value),
    readback = structuredClone(row.readback);
  if (row.id === "timestamp-single") {
    if (!integer(value)) throw Error("timestamp type");
    value = TOKEN;
    readback = TOKEN;
  }
  if (row.id === "multipath-one-clock") {
    if (
      !value ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      !integer(value.first) ||
      !integer(value.second) ||
      value.first !== value.second
    )
      throw Error("timestamp relation");
    value.first = value.second = TOKEN;
    readback.first = readback.second = TOKEN;
  }
  return {
    id: row.id,
    round: row.round,
    preimage: row.preimage,
    request: { method: row.request.method, body: row.request.body },
    before: { status: row.before.status, etag: row.before.etag ?? null },
    response: { status: row.response.status, etag: row.response.etag ?? null },
    after: { status: row.after.status, etag: row.after.etag ?? null },
    value,
    readback,
  };
}
export function compareCase(expected, local) {
  try {
    const actual = maskObservation(local);
    return {
      id: expected.id,
      round: expected.round,
      verdict: isDeepStrictEqual(actual, expected) ? "MATCH" : "MISMATCH",
    };
  } catch {
    return { id: expected.id, round: expected.round, verdict: "MISMATCH" };
  }
}
export function extractFixture(bytes) {
  if (createHash("sha256").update(bytes).digest("hex") !== RAW_SHA)
    throw Error("raw digest mismatch");
  const rows = bytes
    .toString("utf8")
    .trim()
    .split("\n")
    .map(parsed)
    .filter((x) => x.state === "server-value-observation")
    .map((x) => maskObservation(x.observation));
  const required = IDS.flatMap((id) => ["r1", "r2"].map((round) => `${round}/${id}`));
  if (
    rows.length !== 10 ||
    new Set(rows.map((x) => `${x.round}/${x.id}`)).size !== 10 ||
    !required.every((key) => rows.some((x) => `${x.round}/${x.id}` === key))
  )
    throw Error("observation coverage");
  return {
    schemaVersion: 1,
    source: { rawSha256: RAW_SHA, productionReview: "2026-10-29-rtdb-server-values-actual-sol.md" },
    rows,
  };
}
export async function replayCase(expected, send, root) {
  if (
    !/^[A-Za-z0-9_-]+$/.test(root) ||
    !IDS.includes(expected.id) ||
    !["r1", "r2"].includes(expected.round)
  )
    throw Error("invalid scope");
  const path = `/${root}/${expected.round}/${expected.id}.json`;
  const request = async (method, body) => {
    const response = await send({ method, path, ...(body === undefined ? {} : { body }) });
    if (response.status !== 200) throw Error("local response unresolved");
    return { status: response.status, etag: response.etag ?? null, value: parsed(response.body) };
  };
  await request("PUT", JSON.stringify(expected.preimage));
  const before = await request("GET");
  const write = await request(expected.request.method, expected.request.body);
  const after = await request("GET");
  const actual = {
    id: expected.id,
    round: expected.round,
    preimage: before.value,
    request: expected.request,
    before,
    response: write,
    after,
    value: write.value,
    readback: after.value,
  };
  return { result: compareCase(expected, actual), actual };
}
export async function replay(origin, fixture, { fetchImpl = fetch } = {}) {
  const url = new URL(origin);
  if (
    url.protocol !== "http:" ||
    !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  )
    throw Error("local origin required");
  if (fixture?.schemaVersion !== 1 || fixture.rows?.length !== 10) throw Error("fixture invalid");
  const root = `svreplay${randomBytes(8).toString("hex")}`,
    rulesUrl = `${url.origin}/.settings/rules.json`,
    rootUrl = `${url.origin}/${root}.json`;
  const headers = { authorization: "Bearer owner", "content-type": "application/json" };
  let unknown = false;
  const unknownError = () => Object.assign(Error("local outcome unknown"), { ownedRoot: root });
  const fetchLocal = async (u, o = {}) => {
    if (unknown) throw unknownError();
    let res;
    try {
      res = await fetchImpl(u, { ...o, redirect: "manual", signal: AbortSignal.timeout(10000) });
      if (res.status < 200 || res.status >= 500 || (res.status >= 300 && res.status < 400)) {
        unknown = true;
        throw unknownError();
      }
      return {
        status: res.status,
        headers: res.headers,
        text: async () => {
          try {
            return await res.text();
          } catch {
            unknown = true;
            throw unknownError();
          }
        },
      };
    } catch {
      unknown = true;
      throw unknownError();
    }
  };
  const parseLocal = (text) => {
    try {
      return parsed(text);
    } catch {
      unknown = true;
      throw unknownError();
    }
  };
  const baseline = await fetchLocal(rulesUrl, { headers });
  if (baseline.status !== 200) throw Error("rules baseline unresolved");
  const original = await baseline.text();
  let rows;
  try {
    const configured = await fetchLocal(rulesUrl, {
      method: "PUT",
      headers,
      body: JSON.stringify({
        rules: { ".read": false, ".write": false, [root]: { ".read": true, ".write": true } },
      }),
    });
    if (configured.status !== 200) throw Error("rules setup unresolved");
    const send = async (req) => {
      const res = await fetchLocal(`${url.origin}${req.path}`, {
        method: req.method,
        headers,
        body: req.body,
      });
      const body = await res.text();
      parseLocal(body);
      return { status: res.status, etag: res.headers.get("etag"), body };
    };
    rows = [];
    for (const item of fixture.rows) rows.push(await replayCase(item, send, root));
  } finally {
    if (unknown) throw unknownError();
    let failed = false;
    try {
      const del = await fetchLocal(rootUrl, { method: "DELETE", headers });
      const read = await fetchLocal(rootUrl, { headers });
      if (del.status !== 200 || read.status !== 200 || parseLocal(await read.text()) !== null)
        failed = true;
    } catch {
      failed = true;
    }
    if (unknown) throw unknownError();
    try {
      const put = await fetchLocal(rulesUrl, { method: "PUT", headers, body: original });
      const read = await fetchLocal(rulesUrl, { headers });
      if (put.status !== 200 || read.status !== 200 || (await read.text()) !== original)
        failed = true;
    } catch {
      failed = true;
    }
    if (unknown) throw unknownError();
    if (failed) throw Error("cleanup unresolved");
  }
  return { rows, cleanup: { ownedRootAbsent: true, rulesRestored: true } };
}
async function main(args) {
  if (args[0] === "fixture" && args.length === 3) {
    const bytes = await readFile(args[1]);
    await writeFile(args[2], JSON.stringify(extractFixture(bytes), null, 2) + "\n", { flag: "wx" });
    return;
  }
  if (args[0] === "local" && args.length === 4 && ["strict", "ordinary"].includes(args[2])) {
    const fixture = JSON.parse(
      await readFile(
        new URL("./fixtures/production-rest-server-values.json", import.meta.url),
        "utf8",
      ),
    );
    await mkdir(args[3]);
    let result;
    try {
      result = await replay(args[1], fixture);
    } catch (error) {
      if (error.ownedRoot)
        await writeFile(
          `${args[3]}/unknown.json`,
          JSON.stringify({ status: "UNKNOWN", ownedRoot: error.ownedRoot }) + "\n",
          { flag: "wx" },
        );
      throw error;
    }
    await writeFile(
      `${args[3]}/comparison.json`,
      JSON.stringify({ profile: args[2], ...result }, null, 2) + "\n",
      { flag: "wx" },
    );
    console.log(
      JSON.stringify({
        profile: args[2],
        rows: result.rows.length,
        matched: result.rows.filter((x) => x.result.verdict === "MATCH").length,
      }),
    );
    if (result.rows.some((x) => x.result.verdict !== "MATCH")) process.exitCode = 1;
    return;
  }
  throw Error("usage");
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main(process.argv.slice(2)).catch(() => {
    console.error("server value replay stopped");
    process.exitCode = 2;
  });
