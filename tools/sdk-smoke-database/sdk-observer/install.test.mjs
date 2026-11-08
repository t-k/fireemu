// Codex presend review of packet 3 v1.1, Must: the initial Rules install is a mutation like any other. A 5xx (or any unknown status) on it is an
// unknown outcome: exit 3, claims kept, A2 required; a 4xx is an answer. Also the clipped 2xx body of a mutation never lets a recorder report complete.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { run } from './observer.mjs';
import { scriptManifest, sha256, unknownStatus } from './lib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url)), SCRIPT = scriptManifest(HERE).sha256;
const BASELINE = '{\n  "rules": {\n    ".read": false,\n    ".write": false\n  }\n}\n', PREFIX = '/sdkrest20261104', RUN = 'REST-INSTALL-01';

async function world({ installStatus, installApplies = true, mutationBody = null }) {
  const dir = mkdtempSync(path.join(tmpdir(), 'install-')), paths = { owner: path.join(dir, 'owner.md'), lease: path.join(dir, 'lease'), recording: path.join(dir, 'RECORDING') }, state = { rules: BASELINE, puts: 0 };
  writeFileSync(paths.owner, `- 2026-11-04 | RTDB-SMALL-OBSERVER ${RUN} | decision=APPROVE; scriptSha256=${SCRIPT}; directCap=190; adc=1; prefix=${PREFIX}; suite=rest; basis=2217 | coordinator | review.md\n`);
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url), method = init.method ?? 'GET';
    if (u.hostname === 'oauth2.googleapis.com') return new Response(JSON.stringify({ scope: 'https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email', email: 'tester@example.com' }));
    if (u.hostname === 'firebasedatabase.googleapis.com') return new Response(JSON.stringify({ name: 'projects/1/locations/r/instances/ns', type: 'USER_DATABASE', state: 'ACTIVE' }));
    if (u.pathname === '/.settings/rules.json') {
      if (method === 'PUT') { state.puts += 1; if (state.puts === 1) { if (installApplies) state.rules = init.body; return installStatus === 200 ? new Response('{"status":"ok"}') : new Response('{"error":"x"}', { status: installStatus }); } state.rules = init.body; return new Response('{"status":"ok"}'); }
      return new Response(state.rules);
    }
    if (mutationBody && method === 'PUT' && u.pathname.endsWith('/wl.json') && u.searchParams.get('writeSizeLimit') === 'tiny') return new Response(mutationBody, { status: 200 });
    if (u.pathname.endsWith('/etag.json')) return new Response('{"x":1}', { headers: { etag: '"abc="' } });
    return new Response('null');
  };
  const target = { kind: 'production', projectId: 'demo-prod', projectNumber: '1', region: 'r', namespace: 'ns', principalSha256: sha256('tester@example.com'), baselineRulesSha256: sha256(BASELINE), gcloud: '/x', paths };
  const outcome = await run({ target, runId: RUN, prefix: PREFIX, directCap: 190, suite: 'rest', outDir: path.join(dir, 'run') }, { fetchImpl, mint: () => `ya29.${'t'.repeat(40)}` });
  return { dir, paths, state, outcome, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test('unknownStatus: below 200, 3xx and 5xx are unknown; 2xx and 4xx are answers', () => {
  for (const s of [0, 100, 199, 300, 304, 399, 500, 503, 599]) assert.equal(unknownStatus(s), true, String(s));
  for (const s of [200, 204, 299, 400, 401, 404, 412, 499]) assert.equal(unknownStatus(s), false, String(s));
});
for (const status of [503, 500, 302, 199]) {
  test(`the initial Rules install answered ${status} (and applied) is an unknown mutation: exit 3, claims kept, cleanup verified, A2 required`, async () => {
    const w = await world({ installStatus: status });
    try {
      const { exit, result } = w.outcome;
      assert.equal(exit, 3, JSON.stringify(result)); assert.equal(result.status, 'unverified');
      assert.ok(result.unverified.some(u => u.includes('rules-install')), JSON.stringify(result.unverified));
      assert.deepEqual(result.cleanup, { prefix: 'verified', rules: 'verified' }); assert.equal(w.state.rules, BASELINE, 'the baseline Rules are restored');
      assert.equal(existsSync(w.paths.lease), true); assert.equal(existsSync(w.paths.recording), true);
    } finally { w.cleanup(); }
  });
}
test('near miss: an initial install answered 400 is an answer: exit 1, nothing unknown, claims released', async () => {
  const w = await world({ installStatus: 400, installApplies: false });
  try {
    const { exit, result } = w.outcome;
    assert.equal(exit, 1, JSON.stringify(result)); assert.deepEqual(result.unverified, []); assert.equal(result.status, 'failed');
    assert.equal(existsSync(w.paths.lease), false); assert.equal(existsSync(w.paths.recording), false);
  } finally { w.cleanup(); }
});
test('near miss: a normal install (200) is not unknown', async () => {
  const w = await world({ installStatus: 200 });
  try { assert.equal(w.outcome.exit, 0, JSON.stringify(w.outcome.result.unverified)); assert.deepEqual(w.outcome.result.unverified, []); } finally { w.cleanup(); }
});

test('a clipped 2xx body of a mutation (more than 64 KiB) is not complete evidence: the case is not ok, nothing is unknown, the run is incomplete (exit 1)', async () => {
  const w = await world({ installStatus: 200, mutationBody: 'x'.repeat(70000) });
  try {
    const { exit, result } = w.outcome;
    assert.equal(exit, 1, JSON.stringify(result.unverified)); assert.equal(result.status, 'incomplete'); assert.deepEqual(result.unverified, []);
    assert.equal(result.observed < 144, true, `observed ${result.observed}`);
    assert.equal(existsSync(w.paths.lease), false, 'the mutation is known to have succeeded: nothing to recover, the claims are released after the verified cleanup');
  } finally { w.cleanup(); }
});
