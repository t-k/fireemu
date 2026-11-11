// Prints the Node-derived fixture tables of the emulator profile's `Number()` coercion:
//
//   node js_number_table.mjs numbers   Rust rows (raw JSON, Number(JSON.parse(raw))) for
//                                      tests/jwt_hand_made_shapes.rs `NUMBERS`
//   node js_number_table.mjs strings   Rust rows (f64 bits, String(x)) for the unit tests of
//                                      `js_number_to_string` in src/jwt.rs
//
// Nothing is computed by hand: each row is what the Node binary running this script answers.
const radix = (prefix, digits) => JSON.stringify(prefix + digits);
const raws = [
  'null', 'true', 'false', '[]', '[1]', '[0]', '[1788004860]', '[[1788004860]]', '[1,2]', '[null]',
  '[true]', '["7"]', '[[],[]]', '{}', '{"a":1}',
  '""', '"   "', '"12"', '" 12 "', '"+5"', '"-0"', '"1e3"', '"1.5"', '".5"', '"5."', '"+.5e-3"',
  '"-1788004860"', '"1788004860"', '"1788004860.5"',
  '"Infinity"', '"+Infinity"', '"-Infinity"', '"infinity"', '"INFINITY"', '"inf"', '"-inf"',
  '"NaN"', '"nan"', '"1e400"', '"-1e309"', '"1e309"', '"1e-400"',
  '"0x1"', '"0X1F"', '"0x6A92B4FC"', '"0xffffffffffffffffffffffffffffffff"', '"0o17"', '"0b101"',
  '"-0x1"', '"+0x1"', '"0x"', '"0xg"', '"0b2"', '"0o8"', '"0x0"', '"0b0"', '"0o0"',
  '"1_0"', '"1e"', '"e5"', '"--1"', '"1 2"', '"1,5"', '"abc"',
  '"\\u00a01788004860\\u00a0"', '"\\ufeff5"', '"\\u00855"', '"\\u20285\\u2029"',
  '"\\t\\n5\\r\\u000b\\f"', '"\\u200b5"',
  '0', '-1', '1788004860', '1788004860.5', '-1788004860.5', '1e308', '1.7976931348623157e308',
  '-1e308', '9007199254740993', '9223372036854775807', '9223372036854775808',
  '-9223372036854775808', '1e400', '-1e400', '5e-324', '0.0', '-0.0',
  // Overflowing and special numbers inside arrays: the join writes Infinity, 0 and exponents.
  '[1e400]', '[-1e400]', '[[1e400]]', '[[-1e400]]', '[-0]', '[-0.0]', '[1e21]', '[1e-7]',
  '[5e-324]', '[1.7976931348623157e308]', '[1e300,1e300]', '[0.1]', '[123456789012345680000]',
  '[9007199254740993]', '["1e400"]', '[[],[1]]', '[1.5e-7]', '[1e22]', '[-1e21]',
  // Radix strings whose value needs more than 53 bits: one rounding, ties to even.
  radix('0x', '201a86d280cba5a'), radix('0x', '20000000000001'), radix('0x', '20000000000002'),
  radix('0x', '20000000000003'), radix('0x', '20000000000005'), radix('0x', '20000000000006'),
  radix('0x', '20000000000007'), radix('0x', '1fffffffffffff'), radix('0x', '3fffffffffffff'),
  radix('0X', '7fffffffffffffff'), radix('0x', 'ffffffffffffffff'),
  radix('0x', '10000000000000001'), radix('0x', '1000000000000000100000000000000000001'),
  radix('0x', '20000000000000000000000000000000000000000000000000000000000000000000'),
  radix('0o', '400000000000000001'), radix('0o', '400000000000000003'),
  radix('0o', '1777777777777777777777'), radix('0o', '2000000000000000000000'),
  radix('0b', '100000000000000000000000000000000000000000000000000001'),
  radix('0b', '100000000000000000000000000000000000000000000000000011'),
  radix('0b', '100000000000000000000000000000000000000000000000000010'),
  radix('0b', '1'.repeat(54)), radix('0b', '1'.repeat(53)), radix('0B', '1' + '0'.repeat(52) + '11'),
  radix('0b', '1' + '0'.repeat(60)), radix('0x', '1' + '0'.repeat(60)),
  // Past the largest double: Infinity; just under it: finite.
  radix('0x', 'f'.repeat(260)), radix('0x', '1' + '0'.repeat(255)),
];

const rust = (n) => {
  if (Number.isNaN(n)) return 'None';
  if (n === Infinity) return 'Some(f64::INFINITY)';
  if (n === -Infinity) return 'Some(f64::NEG_INFINITY)';
  // Exact: the bits, so no digit is regrouped or rounded by a formatter.
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, n);
  return `Some(f64::from_bits(0x${view.getBigUint64(0).toString(16).padStart(16, '0')}))`;
};

const numbers = () => {
  for (const raw of raws) {
    const value = Number(JSON.parse(raw));
    console.log(`    (${JSON.stringify(raw)}, ${rust(value)}),`);
  }
};

const strings = () => {
  const values = [
    0, -0, 1, -1, 0.1, 1.5, 123456789, 1e20, 1e21, 1.5e21, 1e-6, 1e-7, 1.5e-7, 1.2345e-7,
    123456789012345680000, 1.7976931348623157e308, 5e-324, 2 ** 53, -(2 ** 53), -1e21,
    1788004860.5, 1e100, 0.000001234, 100, 1e5, 12.5, 1e-5, 1.0000000000000002, Infinity,
    -Infinity, NaN,
  ];
  for (const x of values) {
    const view = new DataView(new ArrayBuffer(8));
    view.setFloat64(0, x);
    const bits = view.getBigUint64(0).toString(16).padStart(16, '0');
    console.log(`        (0x${bits}, ${JSON.stringify(String(x))}),`);
  }
};

const mode = process.argv[2];
if (mode === 'numbers') numbers();
else if (mode === 'strings') strings();
else {
  console.error('usage: node js_number_table.mjs numbers|strings');
  process.exit(2);
}
