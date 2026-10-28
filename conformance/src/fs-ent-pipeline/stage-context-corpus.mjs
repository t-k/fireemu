// Fixed read-only observations; dynamic selectors are supplied only by the reviewed runner.
import { fld, grpcStep, pipeline, stage } from './builders.mjs';
import { O8A_PROGRAMS } from './o8a-corpus.mjs';

const str = (stringValue) => ({ stringValue });
const num = (integerValue) => ({ integerValue: String(integerValue) });
const vector = (values) => ({ mapValue: { fields: { __type__: str('__vector__'), value: { arrayValue: { values: values.map((doubleValue) => ({ doubleValue })) } } } } });
const collection = stage('collection', { referenceValue: '/stage' });
const replace = (id, mode, input) => grpcStep(id, pipeline(collection, stage('replace_with', input, str(mode))));
const nearest = (id, measure, values) => grpcStep(id, pipeline(collection, { name: 'find_nearest', args: [fld('vec'), vector(values), str(measure)], options: { limit: num(3), distance_field: fld('dist') } }));

export function stageContextCases() {
  const original = O8A_PROGRAMS.find((x) => x.id.endsWith('/nesting-main'));
  if (!original) throw new Error('original nesting program unavailable');
  return [
    grpcStep('database', pipeline(stage('database'))),
    replace('replace-full', 'full_replace', fld('m')),
    replace('replace-overwrite', 'merge_overwrite_existing', fld('m')),
    replace('replace-keep', 'merge_keep_existing', fld('m')),
    replace('replace-invalid', 'full_replace', num(7)),
    nearest('nearest-euclidean', 'euclidean', [1, 2]),
    nearest('nearest-cosine', 'cosine', [1, 2]),
    nearest('nearest-dot-product', 'dot_product', [1, 2]),
    nearest('nearest-dimension', 'euclidean', [1, 2, 3]),
    ...[48, 100].map((depth) => structuredClone(original.steps.find((x) => x.id === `chain-${depth}-grpc`))),
  ];
}

export function stageContextSeed() {
  const map = (fields) => ({ mapValue: { fields } });
  return [
    ['stage/a', { vec: vector([2, 1]), m: map({ shared: str('new'), added: str('a') }), shared: str('old'), keep: str('a') }],
    ['stage/b', { vec: vector([3, 2]), m: map({ shared: str('new'), added: str('b') }), shared: str('old'), keep: str('b') }],
    ['stage/c', { vec: vector([2, 4]), m: map({ shared: str('new'), added: str('c') }), shared: str('old'), keep: str('c') }],
    ['other/a', { value: str('other') }],
    ['ne/d1', { i: num(1) }],
  ];
}
