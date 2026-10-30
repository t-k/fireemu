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

const auditCases = [
  ['known', 'success', 'first'], ['known', 'etarget', 'last'], ['known', 'other', 'first'],
  ['postpublish', 'success', 'last'], ['postpublish', 'etarget', 'last'], ['postpublish', 'other', 'first'],
  ['known', 'etarget', 'first'], ['known', 'other', 'last'],
];
for (const [phase, outcome, attempt] of auditCases) {
  test(`audit ${phase} ${outcome} ${attempt}`, async () => {
    const { installForAudit, publishAll } = await import('./recover-v0381.mjs');
    let calls = 0; let sleeps = 0; let publishes = 0;
    const etarget = () => Object.assign(new Error('npm failed'), { stdout: Buffer.from(JSON.stringify({ error: { code: 'ETARGET', summary: 'No matching version found for @fireemu/linux-arm64@0.38.1.' } })) });
    const install = async () => {
      calls++;
      if (attempt === 'last' && calls === 1) throw etarget();
      if (outcome === 'etarget') throw etarget();
      if (outcome === 'other') throw new Error('E401');
    };
    const audit = () => installForAudit('@fireemu/linux-arm64', install, { sleep: async () => { sleeps++; }, attempts: 2 });
    const operation = () => publishAll(new Map([['@fireemu/linux-arm64', 1]]), {
      lookup: async () => phase === 'known' ? {} : null, verify: audit,
      publish: async () => { publishes++; }, verifyPublished: audit,
    });
    if (outcome === 'other' || (outcome === 'etarget' && attempt === 'last')) await assert.rejects(operation());
    else if (outcome === 'etarget') await assert.rejects(operation());
    else await operation();
    const expectedCalls = outcome === 'etarget' ? 2 : attempt === 'last' ? 2 : 1;
    assert.equal(calls, expectedCalls); assert.equal(sleeps, expectedCalls - 1);
    assert.equal(publishes, phase === 'postpublish' ? 1 : 0);
  });
}

test('audit retries only ETARGET naming the exact package and version', async () => {
  const { installForAudit } = await import('./recover-v0381.mjs');
  for (const error of [
    { code: 'ETARGET', summary: 'No matching version found for other@0.38.1.' },
    { code: 'E401', summary: 'No matching version found for @fireemu/linux-arm64@0.38.1.' },
  ]) {
    let calls = 0;
    await assert.rejects(installForAudit('@fireemu/linux-arm64', async () => { calls++; throw Object.assign(new Error('failed'), { stdout: Buffer.from(JSON.stringify({ error })) }); }, { sleep: async () => {}, attempts: 2 }));
    assert.equal(calls, 1);
  }
});

test('only linux-arm64 from the exact second recovery run and SHA is accepted', () => {
  const sha = '4bbd2dcc5926d28f8e38da43df0fcc5f0201c9ec';
  const digest = '00'.repeat(64);
  const integrity = `sha512-${Buffer.from(digest, 'hex').toString('base64')}`;
  const statement = { subject: [{ name: 'pkg:npm/%40fireemu/linux-arm64@0.38.1', digest: { sha512: digest } }], predicate: { buildDefinition: { externalParameters: { workflow: { repository: 'https://github.com/t-k/fireemu', path: '.github/workflows/release.yml', ref: 'refs/heads/main' } }, resolvedDependencies: [{ digest: { gitCommit: sha } }] }, runDetails: { metadata: { invocationId: 'https://github.com/t-k/fireemu/actions/runs/41007719982/attempts/1' } } } };
  assert.equal(validateProvenance(statement, '@fireemu/linux-arm64', integrity, sha), true);
  const wrongRun = structuredClone(statement); wrongRun.predicate.runDetails.metadata.invocationId = 'https://github.com/t-k/fireemu/actions/runs/41007719983/attempts/1';
  assert.equal(validateProvenance(wrongRun, '@fireemu/linux-arm64', integrity, sha), false);
  const wrongPackage = structuredClone(statement); wrongPackage.subject[0].name = 'pkg:npm/%40fireemu/linux-x64@0.38.1';
  assert.equal(validateProvenance(wrongPackage, '@fireemu/linux-x64', integrity, sha), false);
});

test('audit ETARGET retries are bounded at five minutes', async () => {
  const { installForAudit } = await import('./recover-v0381.mjs');
  let elapsed = 0; let calls = 0;
  await assert.rejects(installForAudit('@fireemu/linux-arm64', async () => {
    calls++;
    throw Object.assign(new Error('ETARGET'), { stdout: Buffer.from(JSON.stringify({ error: { code: 'ETARGET', summary: 'No matching version found for @fireemu/linux-arm64@0.38.1.' } })) });
  }, { now: () => elapsed, sleep: async ms => { elapsed += ms; } }));
  assert.equal(elapsed, 300_000); assert.equal(calls, 60);
});

test('failed audit verification stops before publishing anything', async () => {
  const { publishAll } = await import('./recover-v0381.mjs');
  let publishes = 0;
  await assert.rejects(publishAll(new Map([['@fireemu/linux-arm64', 1], ['fireemu', 2]]), {
    lookup: async () => ({}), verify: async () => { throw new Error('ETARGET'); },
    publish: async () => { publishes++; }, verifyPublished: async () => assert.fail(),
  }));
  assert.equal(publishes, 0);
});

test('every package already published by these runs is treated as known', async () => {
  const { lookupPhase } = await import('./recover-v0381.mjs');
  for (const name of ['@fireemu/darwin-arm64', '@fireemu/darwin-x64', '@fireemu/linux-arm64', '@fireemu/linux-x64']) assert.equal(lookupPhase(name), 'known');
  assert.equal(lookupPhase('@fireemu/win32-x64'), 'new');
  assert.equal(lookupPhase('fireemu'), 'new');
});

test('audit tolerates ETARGET for over two minutes without republishing', async () => {
  const { installForAudit, publishAll } = await import('./recover-v0381.mjs');
  let elapsed = 0; let calls = 0; let publishes = 0;
  await publishAll(new Map([['@fireemu/linux-arm64', 1]]), {
    lookup: async () => null, verify: async () => assert.fail(),
    publish: async () => { publishes++; },
    verifyPublished: () => installForAudit('@fireemu/linux-arm64', async () => {
      calls++;
      if (elapsed < 125_000) throw Object.assign(new Error('ETARGET'), { stdout: Buffer.from(JSON.stringify({ error: { code: 'ETARGET', summary: 'No matching version found for @fireemu/linux-arm64@0.38.1.' } })) });
    }, { now: () => elapsed, sleep: async ms => { elapsed += ms; } }),
  });
  assert.equal(publishes, 1); assert.equal(elapsed, 125_000); assert.equal(calls, 26);
});

const tarballCases = [
  ['known', 'success', 'first'], ['known', 'missing', 'last'], ['known', 'error', 'first'],
  ['postpublish', 'success', 'last'], ['postpublish', 'missing', 'last'], ['postpublish', 'error', 'first'],
  ['known', 'missing', 'first'], ['known', 'error', 'last'],
];
for (const [phase, outcome, attempt] of tarballCases) {
  test(`tarball ${phase} ${outcome} ${attempt}`, async () => {
    const { fetchTarball, publishAll } = await import('./recover-v0381.mjs');
    let calls = 0; let sleeps = 0; let publishes = 0;
    const verify = () => fetchTarball('https://registry.npmjs.org/file.tgz', {
      fetchFn: async () => {
        calls++;
        if (attempt === 'last' && calls === 1) return { status: 404, ok: false };
        if (outcome === 'missing') return { status: 404, ok: false };
        if (outcome === 'error') return { status: 503, ok: false };
        return { status: 200, ok: true, arrayBuffer: async () => Buffer.from('package') };
      }, sleep: async () => { sleeps++; }, attempts: 2,
    });
    const operation = () => publishAll(new Map([['@fireemu/linux-x64', 1]]), {
      lookup: async () => phase === 'known' ? {} : null, verify,
      publish: async () => { publishes++; }, verifyPublished: verify,
    });
    if (outcome === 'success') await operation(); else await assert.rejects(operation());
    const expectedCalls = outcome === 'missing' ? 2 : attempt === 'last' ? 2 : 1;
    assert.equal(calls, expectedCalls); assert.equal(sleeps, expectedCalls - 1);
    assert.equal(publishes, phase === 'postpublish' ? 1 : 0);
  });
}

test('tarball 404 retry is bounded at five minutes', async () => {
  const { fetchTarball } = await import('./recover-v0381.mjs');
  let elapsed = 0; let calls = 0;
  await assert.rejects(fetchTarball('https://registry.npmjs.org/file.tgz', {
    fetchFn: async () => { calls++; return { status: 404, ok: false }; },
    sleep: async ms => { elapsed += ms; }, now: () => elapsed,
  }), /404/);
  assert.equal(elapsed, 300_000); assert.equal(calls, 60);
});

test('tarball transport, body, and URL failures never retry', async () => {
  const { fetchTarball } = await import('./recover-v0381.mjs');
  let calls = 0;
  await assert.rejects(fetchTarball('https://attacker.invalid/file.tgz', { fetchFn: async () => { calls++; } }));
  assert.equal(calls, 0);
  for (const fetchFn of [async () => { calls++; throw new Error('network'); }, async () => { calls++; return { status: 200, ok: true, arrayBuffer: async () => { throw new Error('body'); } }; }]) {
    calls = 0;
    await assert.rejects(fetchTarball('https://registry.npmjs.org/file.tgz', { fetchFn, sleep: async () => assert.fail() }));
    assert.equal(calls, 1);
  }
});

test('only linux-x64 from the exact third recovery run and SHA is accepted', () => {
  const sha = 'e4d932e62bbf3ced35cccf5c57f8249c19e446dc';
  const digest = '00'.repeat(64);
  const integrity = `sha512-${Buffer.from(digest, 'hex').toString('base64')}`;
  const statement = { subject: [{ name: 'pkg:npm/%40fireemu/linux-x64@0.38.1', digest: { sha512: digest } }], predicate: { buildDefinition: { externalParameters: { workflow: { repository: 'https://github.com/t-k/fireemu', path: '.github/workflows/release.yml', ref: 'refs/heads/main' } }, resolvedDependencies: [{ digest: { gitCommit: sha } }] }, runDetails: { metadata: { invocationId: 'https://github.com/t-k/fireemu/actions/runs/41012136275/attempts/1' } } } };
  assert.equal(validateProvenance(statement, '@fireemu/linux-x64', integrity, sha), true);
  const wrongRun = structuredClone(statement); wrongRun.predicate.runDetails.metadata.invocationId = 'https://github.com/t-k/fireemu/actions/runs/41012136276/attempts/1';
  assert.equal(validateProvenance(wrongRun, '@fireemu/linux-x64', integrity, sha), false);
  const wrongPackage = structuredClone(statement); wrongPackage.subject[0].name = 'pkg:npm/%40fireemu/win32-x64@0.38.1';
  assert.equal(validateProvenance(wrongPackage, '@fireemu/win32-x64', integrity, sha), false);
});

test('tarball propagation can exceed two minutes without republishing', async () => {
  const { fetchTarball, publishAll } = await import('./recover-v0381.mjs');
  let elapsed = 0; let calls = 0; let publishes = 0;
  await publishAll(new Map([['@fireemu/linux-x64', 1]]), {
    lookup: async () => null, verify: async () => assert.fail(),
    publish: async () => { publishes++; },
    verifyPublished: () => fetchTarball('https://registry.npmjs.org/file.tgz', {
      fetchFn: async () => { calls++; return elapsed < 125_000 ? { status: 404, ok: false } : { status: 200, ok: true, arrayBuffer: async () => Buffer.from('package') }; },
      now: () => elapsed, sleep: async ms => { elapsed += ms; },
    }),
  });
  assert.equal(publishes, 1); assert.equal(elapsed, 125_000); assert.equal(calls, 26);
});

test('tarball retry releases the 404 response body before waiting', async () => {
  const { fetchTarball } = await import('./recover-v0381.mjs');
  let cancelled = 0; let calls = 0;
  await fetchTarball('https://registry.npmjs.org/file.tgz', {
    fetchFn: async () => ++calls === 1 ? { status: 404, ok: false, body: { cancel: async () => { cancelled++; } } } : { status: 200, ok: true, arrayBuffer: async () => Buffer.from('package') },
    sleep: async () => assert.equal(cancelled, 1), attempts: 2,
  });
  assert.equal(cancelled, 1);
});
