// Offline replay of recorded REST Rules operators and queries.
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { createHash, randomBytes } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
const RAW = "a9ff0804e9c3345661990431bf91c11ef093fc43c4280cff677f2ca3781b377a";
const parse = JSON.parse;
const digest = b => createHash("sha256").update(b).digest("hex");
function validateRow(row) {
  if (!row || !/^[a-z0-9-]+$/.test(row.id) || !["r1", "r2"].includes(row.round) || !["write", "query"].includes(row.kind) || ![200,401].includes(row.status) || typeof row.predicate !== "string" || !row.request || row.request.path !== `/{ROOT}/${row.round}/${row.id}.json` || !["PUT","GET"].includes(row.request.method) || row.seedResponse?.status !== 200 || typeof row.seedResponse.body !== "string" || typeof row.body !== "string") throw Error("invalid observation");
  parse(row.seedResponse.body); parse(row.body);
  if (row.request.body !== undefined) parse(row.request.body);
  return row;
}
function project(row) {
  const x=structuredClone(validateRow(row));
  x.seedResponse.body=parse(x.seedResponse.body); x.body=parse(x.body);
  if (x.request.body !== undefined) x.request.body=parse(x.request.body);
  return x;
}
export function compareCase(expected, actual) {
  try { return { id: expected.id, round: expected.round, verdict: isDeepStrictEqual(project(expected),project(actual)) ? "MATCH" : "MISMATCH" }; }
  catch { return { id: expected?.id, round: expected?.round, verdict:"MISMATCH" }; }
}
export function extractFixture(bytes) {
  if (digest(bytes)!==RAW) throw Error("raw digest mismatch");
  const all=bytes.toString("utf8").trim().split("\n").map(parse);
  const install=all.filter(x=>x.state==="before-send" && x.id===13 && x.method==="PUT" && x.url.endsWith("/.settings/rules.json"));
  if (install.length!==1) throw Error("rules install missing");
  const global=parse(install[0].body).rules;
  const roots=Object.keys(global).filter(x=>/^rnext1_[a-f0-9]{24}$/.test(x));
  if(roots.length!==1) throw Error("invalid recorded root");
  const root=roots[0], rules=global[root], triples=new Map();
  for(const x of all) if(x.state==="before-send") triples.set(x.id,{request:x}); else if(x.state==="response-headers" && triples.has(x.id)) triples.get(x.id).headers=x; else if(x.state==="response-persisted" && triples.has(x.id)) triples.get(x.id).response=x;
  const rows=all.filter(x=>x.state==="rules-operators-observation").map(({observation:o})=>{
    const path=`/${root}/${o.round}/${o.id}.json`;
    const entries=[...triples.values()].filter(x=>x.request.url.startsWith(`https://fireemu-q-rtdb2.firebaseio.com${path}`) && x.request.phase==="normal");
    if(entries.length!==3) throw Error("request correlation");
    const [seed,client,read]=entries;
    const body=x=>{const b=Buffer.from(x.response.bodyBase64,"base64"); if(digest(b)!==x.response.bodySha256 || b.length!==x.response.bodyBytes) throw Error("response digest"); return b.toString("utf8");};
    const clientUrl=new URL(client.request.url), expectedQuery=new URLSearchParams(o.request.query ?? ""); expectedQuery.set("auth_variable_override","null");
    if(seed.request.method!=="PUT" || seed.request.body!==JSON.stringify(o.seed) || seed.headers.status!==200 || client.request.method!==o.request.method || clientUrl.searchParams.toString()!==expectedQuery.toString() || client.headers.status!==o.status || body(client)!==o.body || read.request.method!=="GET" || read.headers.status!==200 || !isDeepStrictEqual(parse(body(read)),o.readback)) throw Error("request mismatch");
    const rule=rules[o.round]?.[o.id]; if(!rule || rule[o.kind==="write"?".write":".read"]!==o.predicate) throw Error("rule mismatch");
    const request={method:o.request.method,path:`/{ROOT}/${o.round}/${o.id}.json`,...(o.request.query!==undefined?{query:o.request.query}:{}),...(o.request.body!==undefined?{body:o.request.body}:{})};
    return validateRow({id:o.id,round:o.round,kind:o.kind,predicate:o.predicate,seed:o.seed,seedResponse:{status:seed.headers.status,body:body(seed),etag:seed.headers.headers.etag ?? null},request,status:o.status,body:o.body,etag:o.etag ?? null,readback:o.readback,rule});
  });
  if(rows.length!==98 || new Set(rows.map(x=>`${x.round}/${x.id}`)).size!==98 || Object.keys(rules.r1).length!==49 || Object.keys(rules.r2).length!==49 || rows.some(x=>!rows.some(y=>y.id===x.id && y.round!==x.round))) throw Error("incomplete recording");
  return {schemaVersion:1,source:{rawSha256:RAW,productionReview:"2026-10-29-rtdb-rules-operators-actual-sol.md"},globalRules:{...global,["{ROOT}"]:rules,[root]:undefined},rules,rows};
}
export async function replayCase(expected, send, root) {
  validateRow(expected); if(!/^[A-Za-z0-9_-]+$/.test(root)) throw Error("invalid root");
  const path=expected.request.path.replace("{ROOT}",root);
  const seed=await send({method:"PUT",path,body:JSON.stringify(expected.seed)});
  if(seed.status!==200 || !isDeepStrictEqual(parse(seed.body),parse(expected.seedResponse.body))) throw Error("seed unresolved");
  const query=new URLSearchParams(expected.request.query ?? ""); query.set("auth_variable_override","null");
  const client=await send({method:expected.request.method,path,query:`?${query}`,body:expected.request.body});
  const read=await send({method:"GET",path}); if(read.status!==200) throw Error("readback unresolved");
  const actual={...structuredClone(expected),seedResponse:{status:seed.status,body:seed.body,etag:seed.etag ?? null},status:client.status,body:client.body,etag:client.etag ?? null,readback:parse(read.body)};
  return {result:compareCase(expected,actual),actual};
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
  if (
    fixture?.schemaVersion !== 1 ||
    fixture.rows?.length !== 98 ||
    new Set(fixture.rows.map((x) => `${x.round}/${x.id}`)).size !== 98
  )
    throw Error("fixture invalid");
  for (const row of fixture.rows) validateRow(row);
  if (digest(JSON.stringify(fixture)) !== "2d7e6fb426325717fb04af534bfc5724cb5f96c3b766428f6ac49e1838158cca" || !isDeepStrictEqual(fixture.globalRules?.["{ROOT}"], fixture.rules)) throw Error("fixture invalid");
  const root = `operatorsreplay${randomBytes(8).toString("hex")}`,
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
      return parse(text);
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
    if (!fixture.globalRules || !fixture.rules || !isDeepStrictEqual(fixture.globalRules["{ROOT}"], fixture.rules)) throw Error("rules fixture invalid");
    const rules = {rules: {...fixture.globalRules, [root]: fixture.rules}};
    delete rules.rules["{ROOT}"];
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
      await readFile(new URL("./fixtures/production-rules-operators.json", import.meta.url), "utf8"),
    );
    await mkdir(args[3]);
    let result;
    try {
      result = await replay(args[1], fixture);
    } catch (e) {
      if (e.ownedRoot)
        await writeFile(
          `${args[3]}/unknown.json`,
          JSON.stringify({ status: "UNKNOWN", ownedRoot: e.ownedRoot }) + "\n",
          { flag: "wx" },
        );
      throw e;
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
    console.error("Rules operators replay stopped");
    process.exitCode = 2;
  });
