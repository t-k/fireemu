// Offline replay of recorded REST Rules evaluation; no production access.
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { createHash, randomBytes } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
const RAW_SHA = "e4eea118280a740a40ef7df808df8046218fbcfba5c09ac3c380cba78336b56c";
const IDS = [
  "timestamp-valid",
  "timestamp-negative",
  "uid-allow",
  "uid-deny",
  "contains-allow",
  "contains-deny",
  "strict-allow",
  "strict-deny",
];
const TOKEN = "<timestamp>";
const parsed = (s) => {
  try {
    return JSON.parse(s);
  } catch {
    throw Error("invalid JSON");
  }
};
export function maskObservation(row) {
  if (
    !IDS.includes(row?.id) ||
    !["r1", "r2"].includes(row.round) ||
    ![200, 401].includes(row.status) ||
    row.request?.method !== "PUT" ||
    typeof row.request.body !== "string" ||
    !row.rule ||
    typeof row.rule !== "object" ||
    ![null, "object"].includes(row.request.override === null ? null : typeof row.request.override)
  )
    throw Error("invalid observation");
  const override = row.id.startsWith("uid-") ? { uid: "sv-rule-user" } : null;
  if (!isDeepStrictEqual(row.request.override, override)) throw Error("override refused");
  let body = parsed(row.body),
    readback = structuredClone(row.readback);
  if (row.id === "timestamp-valid") {
    if (!Number.isSafeInteger(body) || !Number.isSafeInteger(readback) || body !== readback)
      throw Error("timestamp relation");
    body = readback = TOKEN;
  }
  return {
    id: row.id,
    round: row.round,
    seed: row.seed,
    request: { method: row.request.method, body: row.request.body, override: row.request.override },
    status: row.status,
    body,
    readback,
    etag: row.etag ?? null,
    rule: row.rule,
  };
}
export function compareCase(expected, actual) {
  try {
    return {
      id: expected.id,
      round: expected.round,
      verdict: isDeepStrictEqual(expected, maskObservation(actual)) ? "MATCH" : "MISMATCH",
    };
  } catch {
    return { id: expected.id, round: expected.round, verdict: "MISMATCH" };
  }
}
export function extractFixture(bytes) {
  if (createHash("sha256").update(bytes).digest("hex") !== RAW_SHA)
    throw Error("raw digest mismatch");
  const entries = bytes.toString("utf8").trim().split("\n").map(parsed),
    observations = entries
      .filter((x) => x.state === "rules-language-observation")
      .map((x) => x.observation);
  const installs = entries.filter(
    (x) =>
      x.state === "before-send" &&
      x.method === "PUT" &&
      x.url.includes("/.settings/rules.json") &&
      x.id === 13,
  );
  if (installs.length !== 1) throw Error("rules install missing");
  const rules = parsed(installs[0].body).rules;
  const rows = observations.map((o) => {
    const m = /^\/(rnext1_[a-f0-9]{24})\/(r[12])\/([a-z-]+)\.json$/.exec(o.request?.path ?? "");
    if (!m || m[2] !== o.round || m[3] !== o.id || !rules[m[1]]?.[o.round]?.[o.id])
      throw Error("rule binding");
    return maskObservation({ ...o, rule: rules[m[1]][o.round][o.id] });
  });
  if (
    rows.length !== 16 ||
    new Set(rows.map((x) => `${x.round}/${x.id}`)).size !== 16 ||
    !IDS.every((id) =>
      ["r1", "r2"].every((round) => rows.some((x) => x.id === id && x.round === round)),
    )
  )
    throw Error("observation coverage");
  return {
    schemaVersion: 1,
    source: {
      rawSha256: RAW_SHA,
      productionReview: "2026-10-29-rtdb-rules-language-actual-sol.md",
    },
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
  const seed = await send({ method: "PUT", path, body: JSON.stringify(expected.seed) });
  if (seed.status !== 200 || !isDeepStrictEqual(parsed(seed.body), expected.seed))
    throw Error("seed unresolved");
  const query = `?auth_variable_override=${encodeURIComponent(JSON.stringify(expected.request.override))}`;
  const response = await send({
    method: expected.request.method,
    path,
    query,
    body: expected.request.body,
  });
  const read = await send({ method: "GET", path });
  if (read.status !== 200) throw Error("readback unresolved");
  const actual = {
    id: expected.id,
    round: expected.round,
    seed: expected.seed,
    request: expected.request,
    status: response.status,
    body: response.body,
    readback: parsed(read.body),
    etag: response.etag ?? null,
    rule: expected.rule,
  };
  return { result: compareCase(expected, actual), actual };
}
export async function replay(origin, fixture, { fetchImpl = fetch } = {}) {
  const u = new URL(origin);
  if (
    u.protocol !== "http:" ||
    !["127.0.0.1", "localhost", "[::1]"].includes(u.hostname) ||
    u.username ||
    u.password ||
    u.pathname !== "/" ||
    u.search ||
    u.hash
  )
    throw Error("local origin required");
  if (fixture?.schemaVersion !== 1 || fixture.rows?.length !== 16) throw Error("fixture invalid");
  for (const row of fixture.rows) {
    if (
      !IDS.includes(row?.id) ||
      !["r1", "r2"].includes(row.round) ||
      !isDeepStrictEqual(
        row.request?.override,
        row.id.startsWith("uid-") ? { uid: "sv-rule-user" } : null,
      )
    )
      throw Error("fixture invalid");
  }
  const root = `rulesreplay${randomBytes(8).toString("hex")}`,
    rulesUrl = `${u.origin}/.settings/rules.json`,
    rootUrl = `${u.origin}/${root}.json`,
    headers = { authorization: "Bearer owner", "content-type": "application/json" };
  let unknown = false;
  const unknownError = () => Object.assign(Error("local outcome unknown"), { ownedRoot: root });
  const local = async (url, options = {}) => {
    if (unknown) throw unknownError();
    try {
      const res = await fetchImpl(url, {
        ...options,
        redirect: "manual",
        signal: AbortSignal.timeout(10000),
      });
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
  const baseline = await local(rulesUrl, { headers });
  if (baseline.status !== 200) throw Error("rules baseline unresolved");
  const original = await baseline.text();
  let rows;
  try {
    const branches = { r1: {}, r2: {} };
    for (const item of fixture.rows) branches[item.round][item.id] = item.rule;
    const rules = {
      rules: {
        ".read": false,
        ".write": false,
        [root]: { ".read": false, ready: { ".read": true }, ...branches },
      },
    };
    const setup = await local(rulesUrl, { method: "PUT", headers, body: JSON.stringify(rules) });
    if (setup.status !== 200) throw Error("rules setup unresolved");
    const send = async (req) => {
      const res = await local(`${u.origin}${req.path}${req.query ?? ""}`, {
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
      const del = await local(rootUrl, { method: "DELETE", headers });
      const read = await local(rootUrl, { headers });
      if (del.status !== 200 || read.status !== 200 || parseLocal(await read.text()) !== null)
        failed = true;
    } catch {
      failed = true;
    }
    if (unknown) throw unknownError();
    try {
      const put = await local(rulesUrl, { method: "PUT", headers, body: original });
      const read = await local(rulesUrl, { headers });
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
    await writeFile(
      args[2],
      JSON.stringify(extractFixture(await readFile(args[1])), null, 2) + "\n",
      { flag: "wx" },
    );
    return;
  }
  if (args[0] === "local" && args.length === 4 && ["strict", "ordinary"].includes(args[2])) {
    const fixture = JSON.parse(
      await readFile(new URL("./fixtures/production-rules-language.json", import.meta.url), "utf8"),
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
    console.error("Rules language replay stopped");
    process.exitCode = 2;
  });
