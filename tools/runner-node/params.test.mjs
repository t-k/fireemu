import assert from 'node:assert/strict';
import test from 'node:test';
import { resolveDeclaredParams, resolveWhenDeclared, serializeDefault } from './params.mjs';

// The SDK's classes carry their type as a static member and the declaration as `options`.
function param(type, name, options = {}) {
  const Class = class { static type = type; };
  const value = new Class();
  value.name = name;
  value.options = options;
  return value;
}
const expression = (runtimeValue) => ({ runtimeValue });

test('a value in the environment wins over the declared default, and an empty one is a value', () => {
  const env = { A: 'from-dotenv', B: '' };
  const result = resolveDeclaredParams(
    [param('string', 'A', { default: 'x' }), param('string', 'B', { default: 'y' })],
    env,
  );
  assert.deepEqual(env, { A: 'from-dotenv', B: '' });
  assert.deepEqual(result, { missing: [], defaulted: [] });
});

test('a declared default fills an absent variable in the CLI spelling of each type', () => {
  const env = {};
  const result = resolveDeclaredParams(
    [
      param('string', 'S', { default: 'text' }),
      param('int', 'I', { default: 0 }),
      param('float', 'F', { default: 1.5 }),
      param('boolean', 'T', { default: true }),
      param('boolean', 'U', { default: false }),
      param('list', 'L', { default: ['a', 'b'] }),
    ],
    env,
  );
  assert.deepEqual(env, { S: 'text', I: '0', F: '1.5', T: 'true', U: 'false', L: '["a","b"]' });
  assert.deepEqual(result.missing, []);
  assert.equal(result.defaulted.length, 6);
});

test('a parameter with neither a value nor a default is missing, with its type', () => {
  const env = {};
  const result = resolveDeclaredParams(
    [param('int', 'NEEDS_VALUE'), param('string', 'OK', { default: 'x' })],
    env,
  );
  assert.deepEqual(result.missing, [{ name: 'NEEDS_VALUE', type: 'int' }]);
  assert.equal(env.NEEDS_VALUE, undefined);
  assert.equal(env.OK, 'x');
});

test('secrets are never resolved here, whatever they declare', () => {
  const env = {};
  const result = resolveDeclaredParams(
    [param('secret', 'S', {}), param('secret', 'T', { default: 'ignored' })],
    env,
  );
  assert.deepEqual(result, { missing: [], defaulted: [] });
  assert.deepEqual(env, {});
});

test('a default that is another parameter is evaluated against the environment resolved so far', () => {
  const env = { BASE: 'one' };
  resolveDeclaredParams(
    [param('string', 'DERIVED', { default: expression(() => `${env.BASE}-two`) })],
    env,
  );
  assert.equal(env.DERIVED, 'one-two');
});

test('a default that cannot be evaluated leaves the parameter missing', () => {
  const env = {};
  const result = resolveDeclaredParams(
    [param('string', 'BAD', { default: expression(() => { throw new Error('nope'); }) })],
    env,
  );
  assert.deepEqual(result.missing, [{ name: 'BAD', type: 'string' }]);
});

test('nothing declared, or an unnamed entry, resolves to nothing', () => {
  assert.deepEqual(resolveDeclaredParams(undefined, {}), { missing: [], defaulted: [] });
  assert.deepEqual(resolveDeclaredParams([{}, null], {}), { missing: [], defaulted: [] });
});

test('every combination of presence and default agrees with the rule', () => {
  const defaults = [undefined, 'd', 0, false, [], ['x']];
  for (const type of ['string', 'int', 'float', 'boolean', 'list']) {
    for (const present of [undefined, '', 'v']) {
      for (const def of defaults) {
        const env = present === undefined ? {} : { P: present };
        const options = def === undefined ? {} : { default: def };
        const { missing, defaulted } = resolveDeclaredParams([param(type, 'P', options)], env);
        if (present !== undefined) {
          assert.deepEqual([missing, defaulted], [[], []], `${type} ${present} ${def}`);
          assert.equal(env.P, present);
        } else if (def === undefined) {
          assert.equal(missing.length, 1, `${type} ${def}`);
          assert.equal(env.P, undefined);
        } else {
          assert.equal(missing.length, 0);
          assert.equal(env.P, serializeDefault(def));
        }
      }
    }
  }
});

test('a parameter is resolved as it is declared, so a top-level read sees its default', () => {
  const env = {};
  const declared = [];
  assert.equal(resolveWhenDeclared(declared, env), true);
  declared.push(param('string', 'EARLY', { default: 'now' }));
  assert.equal(env.EARLY, 'now');
  assert.equal(declared.length, 1);
  // A second wrap is refused, so the resolution never nests.
  assert.equal(resolveWhenDeclared(declared, env), false);
  // A parameter without a default is still registered, and left for the final report.
  declared.push(param('int', 'LATE'));
  assert.equal(env.LATE, undefined);
  assert.deepEqual(resolveDeclaredParams(declared, env).missing, [{ name: 'LATE', type: 'int' }]);
  assert.equal(resolveWhenDeclared(undefined, env), false);
});
