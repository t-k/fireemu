import assert from 'node:assert/strict';
import test from 'node:test';

import { CALIBRATION_PHASES } from './fs-ent-pipeline/text-calibration.mjs';

function assertPhaseShape(phase, seedCount) {
  assert.deepEqual(phase.indexFields, ['title', 'body'].slice(0, phase.indexFields.length));
  assert.equal(phase.seed.length, seedCount);
  assert.equal(new Set(phase.seed.map(([path]) => path)).size, seedCount);
  for (const [path, fields] of phase.seed) {
    assert.match(path, /^textobs1\/c-[a-z0-9-]+$/);
    for (const value of Object.values(fields)) assert.equal(typeof value.stringValue, 'string');
  }
  assert.deepEqual(
    phase.queries.map(({ id }) => id),
    ['fox', 'quick', 'conjunction', 'duplicate', 'phrase', 'enhancement-disabled'],
  );
  for (const query of phase.queries) {
    assert.equal(typeof query.text, 'string');
    const score = { functionValue: { name: 'score', args: [] } };
    const expectedOptions = {
      add_fields: { mapValue: { fields: { rank: score } } },
      sort: {
        arrayValue: {
          values: [
            {
              mapValue: {
                fields: {
                  expression: score,
                  direction: { stringValue: 'descending' },
                },
              },
            },
          ],
        },
      },
    };
    if (query.id === 'enhancement-disabled') {
      expectedOptions.query_enhancement = { stringValue: 'disabled' };
    }
    assert.deepEqual(query.options, expectedOptions);
  }
}

function titleFrequency(seed, token) {
  return seed.map(([path, fields]) => [path, (fields.title.stringValue.match(new RegExp(`\\b${token}\\b`, 'g')) ?? []).length]);
}

test('calibration phases have fixed fields, corpus sizes, and scoped seeds', () => {
  assert.deepEqual(CALIBRATION_PHASES.map(({ id }) => id), [
    'one-field',
    'two-fields',
    'corpus-size-control',
  ]);
  assertPhaseShape(CALIBRATION_PHASES[0], 13);
  assert.deepEqual(CALIBRATION_PHASES[0].indexFields, ['title']);
  assertPhaseShape(CALIBRATION_PHASES[1], 13);
  assert.deepEqual(CALIBRATION_PHASES[1].indexFields, ['title', 'body']);
  assertPhaseShape(CALIBRATION_PHASES[2], 21);
  assert.deepEqual(CALIBRATION_PHASES[2].indexFields, ['title', 'body']);
});

test('the seed controls title and body frequency independently', () => {
  const seed = CALIBRATION_PHASES[1].seed;
  const titles = Object.fromEntries(titleFrequency(seed, 'fox'));
  const bodies = Object.fromEntries(seed.map(([path, fields]) => [
    path,
    (fields.body.stringValue.match(/\bfox\b/g) ?? []).length,
  ]));

  assert.deepEqual(
    ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm'].map((key) => titles[`textobs1/c-${key}`]),
    [1, 2, 3, 7, 1, 0, 1, 1, 1, 0, 1, 3, 0],
  );
  assert.deepEqual(
    ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm'].map((key) => bodies[`textobs1/c-${key}`]),
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 4, 1],
  );
});

test('query text and enhancement option are fixed data', () => {
  const queries = CALIBRATION_PHASES[0].queries;
  assert.deepEqual(queries.map(({ id, text }) => [id, text]), [
    ['fox', 'fox'],
    ['quick', 'quick'],
    ['conjunction', 'quick fox'],
    ['duplicate', 'fox fox'],
    ['phrase', '"quick fox"'],
    ['enhancement-disabled', 'fox'],
  ]);
  assert.deepEqual(queries.at(-1).options.query_enhancement, { stringValue: 'disabled' });
  for (const phase of CALIBRATION_PHASES) {
    assert.notEqual(phase.queries[0].options, phase.queries[1].options);
    assert.notEqual(phase.queries[0].options.add_fields, phase.queries[1].options.add_fields);
  }
});

test('coverage and frequency controls detect missing documents and changed term frequency', () => {
  const baseline = structuredClone(CALIBRATION_PHASES[1].seed);
  const baselineCounts = titleFrequency(baseline, 'fox');
  const noop = structuredClone(baseline);
  assert.deepEqual(titleFrequency(noop, 'fox'), baselineCounts);

  const missingDocument = structuredClone(baseline);
  missingDocument.pop();
  assert.notEqual(missingDocument.length, baseline.length);

  const changedFrequency = structuredClone(baseline);
  changedFrequency.find(([path]) => path === 'textobs1/c-d')[1].title.stringValue = 'fox fox';
  assert.notDeepEqual(titleFrequency(changedFrequency, 'fox'), baselineCounts);
});
