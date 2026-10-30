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

const pollingCases = [
  ['known', 'absent', 'last'], ['known', 'present', 'first'], ['new', 'absent', 'first'],
  ['postpublish', 'absent', 'last'], ['postpublish', 'present', 'last'], ['postpublish', 'error', 'first'],
  ['new', 'present', 'first'], ['new', 'error', 'first'], ['known', 'error', 'last'],
];
for (const [phase, outcome, attempt] of pollingCases) {
  test(`polling ${phase} ${outcome} ${attempt}`, async () => {
    const { lookupForPhase } = await import('./recover-v0381.mjs');
    let calls = 0;
    let sleeps = 0;
    const lookup = async () => {
      calls++;
      if (attempt === 'last' && calls === 1) return null;
      if (outcome === 'absent') return null;
      if (outcome === 'error') throw Error('HTTP 503');
      return { version: '0.38.1' };
    };
    const operation = () => lookupForPhase('fireemu', phase, { lookup, sleep: async () => { sleeps++; }, attempts: 2 });
    if (outcome === 'error' || (outcome === 'absent' && phase !== 'new')) await assert.rejects(operation());
    else assert.deepEqual(await operation(), outcome === 'present' ? { version: '0.38.1' } : null);
    const expectedCalls = attempt === 'last' ? 2 : 1;
    assert.equal(calls, expectedCalls);
    assert.equal(sleeps, expectedCalls - 1);
  });
}

test('post-publication polling does not repeat a publish', async () => {
  const { lookupForPhase, publishAll } = await import('./recover-v0381.mjs');
  let publishes = 0;
  let lookups = 0;
  await publishAll(new Map([['fireemu', 1]]), {
    lookup: async () => null,
    verify: async () => assert.fail(),
    publish: async () => { publishes++; },
    verifyPublished: async () => lookupForPhase('fireemu', 'postpublish', {
      lookup: async () => ++lookups < 3 ? null : {}, sleep: async () => {}, attempts: 3,
    }),
  });
  assert.equal(publishes, 1);
  assert.equal(lookups, 3);
});

test('only darwin-x64 from the exact prior recovery run and SHA is accepted', () => {
  const sha = '34f100efc528b734b171dc88f87a1c4502e2c925';
  const digest = '00'.repeat(64);
  const integrity = `sha512-${Buffer.from(digest, 'hex').toString('base64')}`;
  const statement = { subject: [{ name: 'pkg:npm/%40fireemu/darwin-x64@0.38.1', digest: { sha512: digest } }], predicate: { buildDefinition: { externalParameters: { workflow: { repository: 'https://github.com/t-k/fireemu', path: '.github/workflows/release.yml', ref: 'refs/heads/main' } }, resolvedDependencies: [{ digest: { gitCommit: sha } }] }, runDetails: { metadata: { invocationId: 'https://github.com/t-k/fireemu/actions/runs/41001331458/attempts/1' } } } };
  assert.equal(validateProvenance(statement, '@fireemu/darwin-x64', integrity, sha), true);
  const wrongRun = structuredClone(statement); wrongRun.predicate.runDetails.metadata.invocationId = 'https://github.com/t-k/fireemu/actions/runs/41001331459/attempts/1';
  assert.equal(validateProvenance(wrongRun, '@fireemu/darwin-x64', integrity, sha), false);
  const wrongPackage = structuredClone(statement); wrongPackage.subject[0].name = 'pkg:npm/%40fireemu/linux-x64@0.38.1';
  assert.equal(validateProvenance(wrongPackage, '@fireemu/linux-x64', integrity, sha), false);
});

test('polling stops at the five-minute deadline without another request', async () => {
  const { lookupForPhase } = await import('./recover-v0381.mjs');
  let elapsed = 0;
  let calls = 0;
  await assert.rejects(lookupForPhase('fireemu', 'postpublish', {
    lookup: async () => { calls++; return null; },
    sleep: async ms => { elapsed += ms; },
    now: () => elapsed,
  }), /absent/);
  assert.equal(elapsed, 300_000);
  assert.equal(calls, 60);
});

test('non-404 errors stop polling immediately', async () => {
  const { lookupForPhase } = await import('./recover-v0381.mjs');
  for (const message of ['HTTP 409', 'network error', 'integrity mismatch']) {
    let calls = 0;
    await assert.rejects(lookupForPhase('fireemu', 'postpublish', {
      lookup: async () => { calls++; throw Error(message); },
      sleep: async () => assert.fail('must not retry'),
    }), new RegExp(message));
    assert.equal(calls, 1);
  }
});

test('known published versions are never published again when still invisible', async () => {
  const { lookupForPhase, publishAll } = await import('./recover-v0381.mjs');
  let publishes = 0;
  await assert.rejects(publishAll(new Map([['@fireemu/darwin-x64', 1], ['fireemu', 2]]), {
    lookup: name => lookupForPhase(name, 'known', { lookup: async () => null, sleep: async () => {}, attempts: 2 }),
    verify: async () => assert.fail(),
    publish: async () => { publishes++; },
    verifyPublished: async () => assert.fail(),
  }), /absent/);
  assert.equal(publishes, 0);
});

test('post-publication lookup tolerates over two minutes of 404 responses', async () => {
  const { lookupForPhase } = await import('./recover-v0381.mjs');
  let elapsed = 0;
  let calls = 0;
  const result = await lookupForPhase('fireemu', 'postpublish', {
    lookup: async () => { calls++; return elapsed >= 125_000 ? { version: '0.38.1' } : null; },
    sleep: async ms => { elapsed += ms; },
    now: () => elapsed,
  });
  assert.deepEqual(result, { version: '0.38.1' });
  assert.equal(elapsed, 125_000);
  assert.equal(calls, 26);
});
