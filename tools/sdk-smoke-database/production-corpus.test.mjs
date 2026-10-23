import assert from 'node:assert/strict';
import test from 'node:test';

import { rawRestCorpus } from './production-corpus.mjs';

test('raw REST corpus has 62 unique descriptors scoped to the requested round', () => {
  for (const round of [1, 2]) {
    const corpus = rawRestCorpus(round);
    assert.equal(corpus.length, 62);
    assert.equal(new Set(corpus.map(({ id }) => id)).size, 62);

    for (const descriptor of corpus) {
      assert.match(descriptor.id, /^[a-z0-9]+(?:-[a-z0-9]+)*$/);
      assert.match(descriptor.path, new RegExp(`^raw/round${round}/`));
      assert.match(descriptor.path, /\.json$/);
      assert.doesNotMatch(descriptor.path, /(?:https?:|projects\/|\/auth|namespace)/i);
    }
  }
});

test('numeric spellings stay raw and fresh values use distinct nodes', () => {
  const corpus = rawRestCorpus(1);
  const fresh = corpus.filter(({ id }) => id.startsWith('fresh-number-'));
  const puts = fresh.filter(({ method }) => method === 'PUT');
  assert.equal(fresh.length, 20);
  assert.equal(puts.length, 10);
  assert.equal(new Set(puts.map(({ path }) => path)).size, 10);
  assert.deepEqual(puts.map(({ body }) => body), [
    '1', '1.0', '-0.0', '0', '1e7', '9007199254740993',
    '9223372036854775807', '9223372036854775808', '1e400', '-1e400',
  ]);

  const equalValue = corpus.filter(({ id }) => id.startsWith('equal-value-'));
  assert.deepEqual(equalValue.map(({ method, body }) => [method, body]), [
    ['PUT', '1'], ['GET', undefined], ['PUT', '1.0'], ['GET', undefined],
    ['PUT', '-0.0'], ['GET', undefined], ['PUT', '0'], ['GET', undefined],
  ]);
  assert.equal(new Set(equalValue.map(({ path }) => path)).size, 1);
});

test('priority and ETag descriptors preserve exact raw requests', () => {
  const corpus = rawRestCorpus(1);
  const priority = corpus.filter(({ id }) => id.startsWith('priority-'));
  assert.deepEqual(priority.map(({ method, path, body, query }) => [method, path, body, query]), [
    ['PUT', 'raw/round1/priority.json', '{".value":1.0,".priority":2.0}', undefined],
    ['GET', 'raw/round1/priority.json', undefined, 'format=export'],
    ['GET', 'raw/round1/priority/.priority.json', undefined, undefined],
    ['PUT', 'raw/round1/priority/.priority.json', '3.0', undefined],
    ['GET', 'raw/round1/priority.json', undefined, 'format=export'],
  ]);

  const etag = corpus.filter(({ id }) => id.startsWith('etag-'));
  assert.deepEqual(etag.map(({ method, path, body, headers }) => [method, path, body, headers]), [
    ['PUT', 'raw/round1/etag.json', '{"x":1}', undefined],
    ['GET', 'raw/round1/etag.json', undefined, { 'X-Firebase-ETag': 'true' }],
    ['GET', 'raw/round1/missing.json', undefined, { 'X-Firebase-ETag': 'true' }],
    ['PUT', 'raw/round1/etag/x.json', '2', { 'if-match': 'wrong' }],
    ['PUT', 'raw/round1/absent.json', '5', { 'if-match': 'null_etag' }],
    ['GET', 'raw/round1/absent.json', undefined, undefined],
  ]);
});

test('PATCH and array cases retain their raw bodies and ordered requests', () => {
  const corpus = rawRestCorpus(1);
  const patch = corpus.filter(({ id }) => id.startsWith('patch-'));
  assert.deepEqual(patch.map(({ method, path, body }) => [method, path, body]), [
    ['PUT', 'raw/round1/patch.json', '{"x":1,"y":{"z":"s"}}'],
    ['PATCH', 'raw/round1/patch.json', '{"y/z":"t","w":3}'],
    ['GET', 'raw/round1/patch.json', undefined],
    ['PATCH', 'raw/round1/patch.json', '{"q":1,"q/r":2}'],
    ['GET', 'raw/round1/patch.json', undefined],
  ]);

  const arrays = corpus.filter(({ id }) => id.startsWith('array-'));
  assert.deepEqual(arrays.map(({ method, path, body, query }) => [method, path, body, query]), [
    ['PUT', 'raw/round1/array.json', '["a","b",null,"d"]', undefined],
    ['GET', 'raw/round1/array.json', undefined, undefined],
    ['PUT', 'raw/round1/array2.json', '{"0":"a","3":"d"}', undefined],
    ['GET', 'raw/round1/array2.json', undefined, undefined],
    ['GET', 'raw/round1/array2.json', undefined, 'format=export'],
  ]);
});

test('query strings are ordered raw text and validation vectors stay literal', () => {
  const corpus = rawRestCorpus(1);
  const queries = corpus.filter(({ id }) => id.startsWith('query-'));
  assert.equal(queries.length, 8);
  assert.deepEqual(queries.slice(1).map(({ query }) => query), [
    'orderBy="h"',
    'orderBy="h"&startAt=2',
    'orderBy="$key"&limitToFirst=2',
    'orderBy="$value"&limitToFirst=2',
    'orderBy="h"&limitToFirst=0',
    'orderBy="h"&limitToFirst=2&limitToLast=2',
    'orderBy=h',
  ]);
  assert.ok(queries.every(({ method }) => method === 'GET' || method === 'PUT'));

  const validation = corpus.filter(({ id }) => id.startsWith('validation-'));
  assert.deepEqual(validation.map(({ method, path, body }) => [method, path, body]), [
    ['PUT', 'raw/round1/bad-key.json', '{"a.b":1}'],
    ['PUT', 'raw/round1/bad-json.json', '{bad json'],
    ['PUT', 'raw/round1/bad-patch.json', '0'],
    ['PATCH', 'raw/round1/bad-patch.json', '[1,2]'],
    ['GET', 'raw/round1/bad-patch.json', undefined],
  ]);
});

test('only rounds one and two are accepted', () => {
  for (const round of [0, 3, '1']) {
    assert.throws(() => rawRestCorpus(round), RangeError);
  }
});
