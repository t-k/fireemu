import { test } from 'node:test';
import assert from 'node:assert/strict';
import { firstDifference } from './compare.mjs';
import { normalize } from './smokes.mjs';

test('equal values have no difference', () => {
  assert.equal(firstDifference([1, { a: 'x' }], [1, { a: 'x' }]), null);
});

test('the first difference is named by its path', () => {
  assert.equal(firstDifference([1, { a: 'x' }], [1, { a: 'y' }]), '$[1].a: expected "x", got "y"');
  assert.equal(firstDifference([1], [1, 2]), '$[1]: unexpected 2');
  assert.equal(firstDifference({ a: 1 }, {}), '$.a: missing');
  assert.equal(firstDifference([null], [0]), '$[0]: expected null, got 0');
  assert.equal(firstDifference([[1]], [{ 0: 1 }]), '$[0]: expected [1], got {"0":1}');
});

test('server timestamps are normalized and other numbers kept', () => {
  assert.deepEqual(normalize({ t: 1792417166902, n: 5, s: 1.7e12 + 1 }), { t: '<TS>', n: 5, s: '<TS>' });
  assert.equal(normalize(undefined), null);
});
