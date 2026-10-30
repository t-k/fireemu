import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decide, validateProvenance } from './recover-v0381.mjs';

const cases = [
  ['missing', true, true, 'publish'],
  ['present', true, true, 'skip'],
  ['present', false, true, 'error'],
  ['present', true, false, 'error'],
  ['error', true, true, 'error'],
  ['present', false, false, 'error'],
];
for (const [status, integrity, provenance, expected] of cases) {
  test(`registry ${status}, integrity ${integrity}, provenance ${provenance}`, () => {
    if (expected === 'error') assert.throws(() => decide(status, integrity, provenance));
    else assert.equal(decide(status, integrity, provenance), expected);
  });
}

test('accepts only the verified subject, source, ref and workflow for the package', () => {
  const digest = '00'.repeat(64);
  const sha = '24122ce3e375323da91290de11d01b45d14aa9a5';
  const statement = { subject: [{ name: 'pkg:npm/%40fireemu/darwin-arm64@0.38.1', digest: { sha512: digest } }], predicate: { buildDefinition: { externalParameters: { workflow: { repository: 'https://github.com/t-k/fireemu', path: '.github/workflows/release.yml', ref: 'refs/tags/v0.38.1' } }, resolvedDependencies: [{ digest: { gitCommit: sha } }] }, runDetails: { metadata: { invocationId: 'https://github.com/t-k/fireemu/actions/runs/40986239359/attempts/1' } } } };
  const integrity = `sha512-${Buffer.from(digest, 'hex').toString('base64')}`;
  assert.equal(validateProvenance(statement, '@fireemu/darwin-arm64', integrity, sha), true);
  for (const mutate of [
    x => { x.predicate.runDetails.metadata.invocationId = 'https://github.com/t-k/fireemu/actions/runs/1/attempts/1'; },
    x => { x.subject[0].name = 'pkg:npm/other@0.38.1'; },
    x => { x.subject[0].digest.sha512 = 'ff'.repeat(64); },
    x => { x.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit = 'bad'; },
    x => { x.predicate.buildDefinition.externalParameters.workflow.path = 'other.yml'; },
    x => { x.predicate.buildDefinition.externalParameters.workflow.ref = 'refs/heads/main'; },
  ]) { const bad = structuredClone(statement); mutate(bad); assert.equal(validateProvenance(bad, '@fireemu/darwin-arm64', integrity, sha), false); }
});

test('preflights every package before publishing and publishes launcher last', async () => {
  const { publishAll } = await import('./recover-v0381.mjs');
  const events = [];
  const packages = new Map([['@fireemu/a', 1], ['@fireemu/b', 2], ['fireemu', 3]]);
  await publishAll(packages, {
    lookup: async name => { events.push(`lookup:${name}`); return null; },
    verify: async () => assert.fail('absent packages are not verified'),
    publish: async name => { events.push(`publish:${name}`); },
    verifyPublished: async name => { events.push(`verify:${name}`); },
  });
  assert.deepEqual(events, ['lookup:@fireemu/a', 'lookup:@fireemu/b', 'lookup:fireemu', 'publish:@fireemu/a', 'verify:@fireemu/a', 'publish:@fireemu/b', 'verify:@fireemu/b', 'publish:fireemu', 'verify:fireemu']);
});

test('preflight and publication errors stop before the launcher', async () => {
  const { publishAll } = await import('./recover-v0381.mjs');
  for (const failAt of ['lookup', 'verify', 'publish', 'verifyPublished']) {
    const published = [];
    const operations = {
      lookup: async () => { if (failAt === 'lookup') throw Error('lookup'); return failAt === 'verify' ? {} : null; },
      verify: async () => { throw Error('verify'); },
      publish: async name => { published.push(name); if (failAt === 'publish') throw Error('publish'); },
      verifyPublished: async () => { if (failAt === 'verifyPublished') throw Error('verifyPublished'); },
    };
    await assert.rejects(publishAll(new Map([['@fireemu/a', 1], ['fireemu', 2]]), operations));
    assert.ok(!published.includes('fireemu'));
  }
});

test('preflight does not publish and existing packages must verify before skipping', async () => {
  const { publishAll } = await import('./recover-v0381.mjs');
  const calls = [];
  const packages = new Map([['@fireemu/a', 1], ['fireemu', 2]]);
  const operations = {
    lookup: async name => name === '@fireemu/a' ? {} : null,
    verify: async name => { calls.push(`verified:${name}`); },
    publish: async name => { calls.push(`published:${name}`); },
    verifyPublished: async name => { calls.push(`confirmed:${name}`); },
  };
  await publishAll(packages, operations, true);
  assert.deepEqual(calls, ['verified:@fireemu/a']);
  calls.length = 0;
  await publishAll(packages, operations);
  assert.deepEqual(calls, ['verified:@fireemu/a', 'published:fireemu', 'confirmed:fireemu']);
});

test('registry treats only HTTP 404 as absent and rejects malformed or failing replies', async () => {
  const { registry } = await import('./recover-v0381.mjs');
  const original = globalThis.fetch;
  try {
    globalThis.fetch = async () => ({ status: 404, ok: false });
    assert.equal(await registry('fireemu'), null);
    globalThis.fetch = async () => ({ status: 503, ok: false });
    await assert.rejects(registry('fireemu'), /HTTP 503/);
    globalThis.fetch = async () => ({ status: 200, ok: true, json: async () => ({ name: 'other', version: '0.38.1', dist: { integrity: 'x' } }) });
    await assert.rejects(registry('fireemu'), /metadata/);
  } finally { globalThis.fetch = original; }
});

test('child processes receive only the credentials their operation requires', async () => {
  const { childEnvironment } = await import('./recover-v0381.mjs');
  const env = { GH_TOKEN: 'gh', ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'oidc', ACTIONS_ID_TOKEN_REQUEST_URL: 'url', PATH: '/bin' };
  assert.deepEqual(childEnvironment('gh', ['api'], env), { GH_TOKEN: 'gh', PATH: '/bin' });
  assert.deepEqual(childEnvironment('npm', ['pack'], env), { PATH: '/bin' });
  assert.deepEqual(childEnvironment('npm', ['publish'], env), { ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'oidc', ACTIONS_ID_TOKEN_REQUEST_URL: 'url', PATH: '/bin' });
});
