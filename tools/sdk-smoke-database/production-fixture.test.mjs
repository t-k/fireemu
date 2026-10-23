import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { rawRestCorpus } from './production-corpus.mjs';

const fixtureUrl = new URL('./fixtures/production-rest.json', import.meta.url);

function corpusDigest() {
  const rounds = [rawRestCorpus(1), rawRestCorpus(2)];
  return createHash('sha256').update(JSON.stringify(rounds)).digest('hex');
}

function assertFixtureCoverage(fixture) {
  assert.equal(fixture.version, 1);
  assert.equal(fixture.observedAt, '2026-10-23');
  assert.equal(fixture.source.publicCommit, 'b8399bfe1');
  assert.equal(fixture.source.corpusSha256, corpusDigest());
  assert.equal(fixture.rounds.length, 2);

  for (let index = 0; index < 2; index += 1) {
    const round = index + 1;
    const expected = rawRestCorpus(round);
    const actual = fixture.rounds[index];
    assert.equal(actual.round, round);
    assert.equal(actual.rows.length, expected.length);
    assert.deepEqual(
      actual.rows.map(({ id, method, path }) => ({ id, method, path })),
      expected.map(({ id, method, path }) => ({ id, method, path })),
    );
    for (const row of actual.rows) {
      assert.equal(typeof row.status, 'number');
      assert.equal(typeof row.bodyText, 'string');
      assert.ok(row.etag === null || typeof row.etag === 'string');
    }
  }
}

test('public production fixture tracks both raw corpus rounds and digest', async () => {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  assertFixtureCoverage(fixture);
});

test('production response bodies remain text with observed numeric spellings', async () => {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  const rows = fixture.rounds[0].rows;
  const bodyFor = (id) => rows.find((row) => row.id === id).bodyText;

  assert.equal(bodyFor('fresh-number-1-get'), '1.0');
  assert.equal(bodyFor('fresh-number-2-get'), '-0.0');
  assert.equal(bodyFor('fresh-number-4-get'), '1.0E7');
  assert.equal(bodyFor('fresh-number-5-get'), '9007199254740993');
  assert.equal(bodyFor('fresh-number-6-get'), '9223372036854775807');
  assert.equal(bodyFor('fresh-number-7-get'), '9.223372036854776E18');
});

test('ETag evidence retains only the response ETag value or null', async () => {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  const rows = fixture.rounds.flatMap(({ rows: roundRows }) => roundRows);
  assert.ok(rows.some(({ etag }) => typeof etag === 'string'));
  assert.ok(rows.some(({ etag }) => etag === null));
  for (const row of rows) {
    assert.deepEqual(Object.keys(row).sort(), ['bodyText', 'etag', 'id', 'method', 'path', 'status']);
  }
});

test('M14 fixture records every expression, context, and round as observed refusals', async () => {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  assert.equal(fixture.m14.length, 8 * 3 * 2);
  const keys = new Set();
  for (const row of fixture.m14) {
    keys.add(`${row.round}:${row.expressionIndex}:${row.context}`);
    assert.equal(typeof row.expression, 'string');
    assert.ok(['read', 'write', 'validate'].includes(row.context));
    assert.equal(row.status, 400);
    assert.equal(typeof row.bodyText, 'string');
    assert.match(row.bodyText, /could not determinize efficiently/i);
    assert.doesNotMatch(row.bodyText, /parity\d{8}/);
  }
  assert.equal(keys.size, 48);
});

test('fixture excludes private identity, secrets, and Rules source material', async () => {
  const text = await readFile(fixtureUrl, 'utf8');
  assert.doesNotMatch(text, /synthetic-project-number-000000000000|synthetic-db\.example\.invalid|synthetic-account@example\.invalid/i);
  assert.doesNotMatch(text, /https?:\/\/|firebaseio\.com|\.settings\/rules|"rules"\s*:/i);
  assert.doesNotMatch(text, /Bearer\s|ya29\.|AIza[0-9A-Za-z_-]{20,}|private_key|service_account/i);
  assert.doesNotMatch(text, /"(?:admin|identity|origin|projectNumber|namespace|instance)"\s*:/i);
});

test('coverage checks detect missing rows and numeric text mutation', async () => {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  const missingRow = structuredClone(fixture);
  missingRow.rounds[0].rows.pop();
  assert.throws(() => assertFixtureCoverage(missingRow));

  const changedNumber = structuredClone(fixture);
  const row = changedNumber.rounds[0].rows.find(({ id }) => id === 'fresh-number-1-get');
  row.bodyText = '1';
  assert.throws(() => assert.equal(row.bodyText, '1.0'));
});
