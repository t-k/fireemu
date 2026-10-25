// CV01/CV05: replay the recorded production REST corpus (fixtures/production-rest.json) against a
// local fireemu and judge every answer.
//
//   node tools/sdk-smoke-database/rest-replay.mjs local --fireemu <binary> --out <new dir>
//
// It starts `fireemu up --only auth,database` in the strict profile on free loopback ports,
// installs the Rules the production instance had, sends the 124 corpus requests in their recorded
// order (two rounds), then loads the 48 M14 Rules sources, and stops the server. Each REST row is
// MATCH (status, body bytes and ETag equal), KNOWN_DIFFERENCE (only the member order of the JSON
// body differs, on the two rows recorded as such) or MISMATCH. M14 rows compare status and bytes.
// `comparison.json` holds every verdict and the local answer; nothing is sent to production.
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';

import { rawRestCorpus } from './production-corpus.mjs';

export const FIXTURE = './fixtures/production-rest.json';
export const DATA_ROOT = 'parity20261023';
// The Rules of the production instance during the recording (rtdb02-v2).
export const RULES = {
  rules: {
    '.read': false,
    '.write': false,
    [DATA_ROOT]: {
      raw: { '.read': true, '.write': true, $round: { query: { '.indexOn': ['h'] } } },
      sdk: { '.read': true, '.write': true },
      protected: { '.read': false, '.write': false },
    },
  },
};
// Rows where production answered the same JSON with another member order (both rounds): the PATCH
// answer keeps the request's order, and the orderBy query answer lists children in query order.
export const KNOWN_RAW_ORDER = new Set(['patch-update-nested-and-add', 'query-get-1']);
// The fixture masks the data root inside one error message.
const ROOT_MASK = '{root}';

/**
 * The bytes Python's `json.dumps` writes with its defaults, as the recorder sent every Rules
 * source: ", " and ": " separators and every code unit above U+007F escaped. Production reports
 * Rules errors by column, so the replay must upload the same text.
 */
export function pythonJsonDumps(value) {
  if (Array.isArray(value)) return `[${value.map(pythonJsonDumps).join(', ')}]`;
  if (value !== null && typeof value === 'object') return `{${Object.entries(value).map(([k, v]) => `${pythonJsonDumps(k)}: ${pythonJsonDumps(v)}`).join(', ')}}`;
  if (typeof value === 'string') return JSON.stringify(value).replace(/[\u0080-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
  if (typeof value === 'number' && !Number.isInteger(value)) throw Error('only integers are serialized');
  return JSON.stringify(value);
}

export function m14Rules(expression, context) {
  const probe = { '.read': true, '.write': true, [`.${context}`]: expression };
  return { rules: { '.read': false, '.write': false, [DATA_ROOT]: { regex: { probe } } } };
}

/** The corpus requests in recorded order, with their fixture row ids. */
export function localRequests(fixture) {
  return fixture.rounds.flatMap(({ round }) => rawRestCorpus(round).map((d) => ({
    round,
    id: d.id,
    method: d.method,
    url: `/${DATA_ROOT}/${d.path}${d.query ? `?${d.query}` : ''}`,
    body: d.body,
    headers: d.headers ?? {},
  })));
}

const parse = (text) => { try { return { json: JSON.parse(text) }; } catch { return { text }; } };
// Called only when the bytes differ: equal parsed JSON then means another member order.
const memberOrderOnly = (a, b) => isDeepStrictEqual(parse(a), parse(b));

export function judgeRow(round, production, local) {
  const expected = production.bodyText.includes(ROOT_MASK) ? production.bodyText.replaceAll(ROOT_MASK, DATA_ROOT) : production.bodyText;
  const differences = [];
  if (local.status !== production.status) differences.push('status');
  if (local.etag !== production.etag) differences.push('etag');
  if (local.bodyText !== expected) differences.push(memberOrderOnly(local.bodyText, expected) ? 'raw-key-order' : 'body');
  const known = differences.length === 1 && differences[0] === 'raw-key-order' && KNOWN_RAW_ORDER.has(production.id);
  return { round, id: production.id, verdict: differences.length === 0 ? 'MATCH' : known ? 'KNOWN_DIFFERENCE' : 'MISMATCH', differences, production: { status: production.status, bodyText: production.bodyText, etag: production.etag }, local };
}

export function judgeM14(production, local) {
  const same = local.status === production.status && local.bodyText === production.bodyText;
  return { round: production.round, expressionIndex: production.expressionIndex, context: production.context, verdict: same ? 'MATCH' : 'MISMATCH', local: { status: local.status, bodyText: local.bodyText } };
}

const count = (rows) => rows.reduce((acc, r) => ({ ...acc, [r.verdict]: (acc[r.verdict] ?? 0) + 1 }), {});

export function summarize(rows, m14) {
  return { rows: rows.length, m14Rows: m14.length, verdicts: count(rows), m14Verdicts: count(m14), pass: rows.length + m14.length > 0 && [...rows, ...m14].every((r) => r.verdict !== 'MISMATCH') };
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { const { port } = server.address(); server.close(() => resolve(port)); });
  });
}

async function send(origin, { method, url, body, headers }) {
  const response = await fetch(`${origin}${url}`, { method, body, headers, signal: AbortSignal.timeout(10000) });
  return { status: response.status, bodyText: await response.text(), etag: response.headers.get('etag') };
}

async function runLocal({ fireemu, out }) {
  mkdirSync(out); // refuses an existing directory
  const fixture = JSON.parse(readFileSync(new URL(FIXTURE, import.meta.url), 'utf8'));
  const [dbPort, httpPort] = [await freePort(), await freePort()];
  const config = path.join(out, 'config.json');
  writeFileSync(config, `${JSON.stringify({ schemaVersion: 1, profile: 'strict', daemon: { authProject: 'demo-rtdb-prodcompare', databasePort: dbPort, httpPort, hubPort: 0, uiPort: 0, loggingPort: 0 } })}\n`);
  const ready = path.join(out, 'ready.json');
  const child = spawn(fireemu, ['up', '--no-config-discovery', '--config', config, '--only', 'auth,database', '--database-port', String(dbPort), '--http-port', String(httpPort), '--hub-port', '0', '--ui-port', '0', '--logging-port', '0', '--ready-file', ready, '--owner-stdin'], { stdio: ['pipe', 'ignore', 'inherit'], detached: true });
  const exited = new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal })));
  try {
    for (let i = 0; !(existsSync(ready) && readFileSync(ready, 'utf8').length > 0); i++) {
      if (i > 150) throw Error('fireemu did not become ready');
      await new Promise((r) => setTimeout(r, 200));
    }
    const origin = `http://127.0.0.1:${dbPort}`;
    const owner = { authorization: 'Bearer owner' };
    const rules = await send(origin, { method: 'PUT', url: '/.settings/rules.json', body: pythonJsonDumps(RULES), headers: owner });
    if (rules.status !== 200) throw Error(`installing the Rules answered ${rules.status}`);
    const productionRows = fixture.rounds.flatMap((round) => round.rows);
    const rows = [];
    for (const [i, request] of localRequests(fixture).entries()) rows.push(judgeRow(request.round, productionRows[i], await send(origin, request)));
    const m14 = [];
    for (const production of fixture.m14) {
      const local = await send(origin, { method: 'PUT', url: '/.settings/rules.json', body: pythonJsonDumps(m14Rules(production.expression, production.context)), headers: owner });
      m14.push(judgeM14(production, local));
    }
    return { fixture: { observedAt: fixture.observedAt, corpusSha256: fixture.source.corpusSha256 }, summary: summarize(rows, m14), rows, m14 };
  } finally {
    child.stdin.end(); // --owner-stdin: closing stdin stops the server
    const timer = setTimeout(() => { try { process.kill(-child.pid, 'SIGTERM'); } catch {} }, 10000);
    const status = await exited;
    clearTimeout(timer);
    console.error(`fireemu exited (${status.code ?? status.signal})`);
  }
}

async function main(argv) {
  const opt = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  if (argv[0] !== 'local' || !opt('--out') || !opt('--fireemu')) throw Error('usage: local --fireemu <binary> --out <new dir>');
  const result = await runLocal({ fireemu: opt('--fireemu'), out: opt('--out') });
  writeFileSync(path.join(opt('--out'), 'comparison.json'), `${JSON.stringify(result, null, 1)}\n`);
  console.log(JSON.stringify(result.summary));
  return result.summary.pass ? 0 : 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => { console.error(`rest-replay: ${e.message}`); process.exitCode = 2; });
}
