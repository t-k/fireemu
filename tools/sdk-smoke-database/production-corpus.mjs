const freshNumericBodies = [
  '1',
  '1.0',
  '-0.0',
  '0',
  '1e7',
  '9007199254740993',
  '9223372036854775807',
  '9223372036854775808',
  '1e400',
  '-1e400',
];

const queryStrings = [
  'orderBy="h"',
  'orderBy="h"&startAt=2',
  'orderBy="$key"&limitToFirst=2',
  'orderBy="$value"&limitToFirst=2',
  'orderBy="h"&limitToFirst=0',
  'orderBy="h"&limitToFirst=2&limitToLast=2',
  'orderBy=h',
];

export function rawRestCorpus(round) {
  if (round !== 1 && round !== 2) {
    throw new RangeError('round must be the integer 1 or 2');
  }

  const prefix = `raw/round${round}/`;
  const descriptors = [];
  const add = (id, method, relativePath, fields = {}) => {
    descriptors.push({ id, method, path: `${prefix}${relativePath}`, ...fields });
  };

  freshNumericBodies.forEach((body, index) => {
    const node = `number${index}`;
    add(`fresh-number-${index}-put`, 'PUT', `${node}.json`, { body });
    add(`fresh-number-${index}-get`, 'GET', `${node}.json`);
  });

  for (const [id, method, body] of [
    ['put-one', 'PUT', '1'],
    ['get-one', 'GET'],
    ['put-one-point-zero', 'PUT', '1.0'],
    ['get-one-point-zero', 'GET'],
    ['put-negative-zero-point-zero', 'PUT', '-0.0'],
    ['get-negative-zero-point-zero', 'GET'],
    ['put-zero', 'PUT', '0'],
    ['get-zero', 'GET'],
  ]) {
    add(`equal-value-${id}`, method, 'equal-value.json', body === undefined ? {} : { body });
  }

  add('priority-put-value', 'PUT', 'priority.json', { body: '{".value":1.0,".priority":2.0}' });
  add('priority-get-export-before', 'GET', 'priority.json', { query: 'format=export' });
  add('priority-get-priority', 'GET', 'priority/.priority.json');
  add('priority-put-priority', 'PUT', 'priority/.priority.json', { body: '3.0' });
  add('priority-get-export-after', 'GET', 'priority.json', { query: 'format=export' });

  add('etag-put-value', 'PUT', 'etag.json', { body: '{"x":1}' });
  add('etag-get-value', 'GET', 'etag.json', { headers: { 'X-Firebase-ETag': 'true' } });
  add('etag-get-missing', 'GET', 'missing.json', { headers: { 'X-Firebase-ETag': 'true' } });
  add('etag-put-if-match-wrong', 'PUT', 'etag/x.json', { body: '2', headers: { 'if-match': 'wrong' } });
  add('etag-put-if-match-null-etag', 'PUT', 'absent.json', { body: '5', headers: { 'if-match': 'null_etag' } });
  add('etag-get-after-conditional-put', 'GET', 'absent.json');

  add('patch-put-initial', 'PUT', 'patch.json', { body: '{"x":1,"y":{"z":"s"}}' });
  add('patch-update-nested-and-add', 'PATCH', 'patch.json', { body: '{"y/z":"t","w":3}' });
  add('patch-get-after-update', 'GET', 'patch.json');
  add('patch-conflicting-keys', 'PATCH', 'patch.json', { body: '{"q":1,"q/r":2}' });
  add('patch-get-after-conflicting-keys', 'GET', 'patch.json');

  add('array-put-native', 'PUT', 'array.json', { body: '["a","b",null,"d"]' });
  add('array-get-native', 'GET', 'array.json');
  add('array-put-indexed-object', 'PUT', 'array2.json', { body: '{"0":"a","3":"d"}' });
  add('array-get-indexed-object', 'GET', 'array2.json');
  add('array-get-indexed-object-export', 'GET', 'array2.json', { query: 'format=export' });

  add('query-put-mixed-children', 'PUT', 'query.json', {
    body: '{"a":{"h":3},"b":{"h":1},"c":{"h":2},"d":{},"10":{"h":5},"2":{"h":5}}',
  });
  queryStrings.forEach((query, index) => {
    add(`query-get-${index}`, 'GET', 'query.json', { query });
  });

  add('validation-put-bad-key', 'PUT', 'bad-key.json', { body: '{"a.b":1}' });
  add('validation-put-bad-json', 'PUT', 'bad-json.json', { body: '{bad json' });
  add('validation-put-scalar-patch-target', 'PUT', 'bad-patch.json', { body: '0' });
  add('validation-patch-array-body', 'PATCH', 'bad-patch.json', { body: '[1,2]' });
  add('validation-get-bad-patch', 'GET', 'bad-patch.json');

  return descriptors;
}
