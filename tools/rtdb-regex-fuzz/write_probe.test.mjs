import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const runner = fileURLToPath(new URL('./write_probe.mjs', import.meta.url));

// Record each actual operation as the returned tree. This isolates corpus selection from
// network timing while exercising the runner's REST, realtime and fixed-control paths.
const transport = `
const trees = new Map();
globalThis.fetch = async (input, options) => {
  const url = new URL(input);
  const ns = url.searchParams.get('ns');
  if (options.method !== 'GET' && !url.pathname.includes('.settings')) {
    trees.set(ns, {method: options.method, path: url.pathname, body: options.body ?? null});
  }
  return new Response(JSON.stringify(trees.get(ns) ?? null), {status: 200});
};
globalThis.WebSocket = class {
  constructor(input) {
    this.ns = new URL(input).searchParams.get('ns');
    queueMicrotask(() => this.onmessage({data: JSON.stringify({t: 'c'})}));
  }
  send(input) {
    const message = JSON.parse(input);
    if (!['auth', 'gauth'].includes(message.d.a)) trees.set(this.ns, message.d);
    queueMicrotask(() => this.onmessage({data: JSON.stringify({t: 'd', d: {r: message.d.r, b: {s: 'ok'}}})}));
  }
  close() {}
};
globalThis.setTimeout = (callback, delay) => {
  if (delay < 10000) queueMicrotask(callback);
};
`;

function run(directory, name, corpus, offset) {
  const input = join(directory, `${name}.json`);
  const output = join(directory, `${name}-out.json`);
  writeFileSync(input, JSON.stringify(corpus));
  const args = ['--import', `data:text/javascript,${encodeURIComponent(transport)}`, runner,
    '127.0.0.1:1', input, output, '1'];
  if (offset !== undefined) args.push(String(offset));
  const result = spawnSync(process.execPath, args, {encoding: 'utf8', timeout: 5000});
  return {...result, rows: result.status === 0 ? JSON.parse(readFileSync(output, 'utf8')) : null};
}

test('a corpus chunk keeps the original operation bodies, identities and row indices', () => {
  const directory = mkdtempSync(join(tmpdir(), 'rtdb-write-offset-'));
  try {
    const corpus = [
      {expr: 'true', place: 'W'},
      {expr: 'false', place: 'V'},
      {expr: 'newData.exists()', place: 'VC'},
      {expr: 'true', place: 'V', bodies: {od_merge: {a: 5, b: 5}, prio: 9}},
    ];
    const whole = run(directory, 'whole', corpus);
    const chunk = run(directory, 'chunk', corpus.slice(2), 2);
    assert.equal(whole.status, 0, whole.stderr);
    assert.equal(chunk.status, 0, chunk.stderr);
    assert.deepEqual(chunk.rows, whole.rows.slice(4));
    assert.equal(chunk.rows.length, 4);
    for (const row of chunk.rows) {
      assert.equal(Object.values(row).filter(Array.isArray).length, 36);
    }
  } finally {
    rmSync(directory, {recursive: true});
  }
});

test('invalid corpus offsets are refused before contacting an endpoint', () => {
  const directory = mkdtempSync(join(tmpdir(), 'rtdb-write-offset-'));
  try {
    for (const offset of [-1, 1.5, 'bad', Number.MAX_SAFE_INTEGER + 1]) {
      const result = run(directory, `invalid-${offset}`, [], offset);
      assert.notEqual(result.status, 0, String(offset));
      assert.match(result.stderr, /corpus offset/i);
    }
  } finally {
    rmSync(directory, {recursive: true});
  }
});
