// Records the official emulator (firebase-database-emulator 4.11.2, the pinned jar) on the Rules constructs production was
// recorded loading in RTDB-RULES-SYNTAX-20261108-01: query.endBefore, query.isOrderByChild(), the OrderByKey, OrderByValue and
// OrderByPriority names, http.encodeURL(), a method read without a call and a call through a non-member callee. Each row is
// one `.read` expression at /t (with the `.indexOn` beside it), whether the rules loaded (and the refusal text), and the status
// of a read of /t by user u1 with the REST query given. The format is that of
// crates/fireemu-core-database/tests/fixtures/rules-query-orderby-official-emulator-4.11.2.json.
//
//   node tools/rtdb-regex-fuzz/record_query_syntax.mjs <new output file>
import { writeFileSync } from 'node:fs';

import { startJar } from '../sdk-smoke-database/jar.mjs';

const q = s => encodeURIComponent(`"${s}"`).replace(/'/g, '%27');
export const INDEX_ON = ['m', 'a/b', '.value'];
export const QUERIES = [
  '',
  `orderBy=${q('$key')}`,
  `orderBy=${q('$value')}`,
  `orderBy=${q('$priority')}`,
  `orderBy=${q('m')}`,
  `orderBy=${q('a/b')}`,
  `orderBy=${q('m')}&endBefore=2`,
  `orderBy=${q('m')}&endAt=2`,
  `orderBy=${q('m')}&equalTo=2`,
  `orderBy=${q('$key')}&endBefore=${q('b')}&limitToLast=1`,
];
const ENCODED = [
  ['aZ09.-*_~', 'aZ09.-*_%7E'], ["!\\'()", '%21%27%28%29'], ['+/?#&=%', '%2B%2F%3F%23%26%3D%25'], ['a b', 'a%20b'],
  ['\\u00e9\\u00df', '%C3%A9%C3%9F'], ['\\uD83D\\uDE00', '%F0%9F%98%80'], ['\\uD83D', '%3F'], ['\\u2028 \\t', '%E2%80%A8%20%09'],
];
export const EXPRESSIONS = [
  "query.isOrderByChild('m')", "query.isOrderByChild('/m/')", "query.isOrderByChild('a/b')", "query.isOrderByChild('a//b')",
  "query.isOrderByChild('.priority')", "query.isOrderByChild('.value')", "!query.isOrderByChild('m')", "!query.isOrderByChild('')",
  "!query.isOrderByChild('$key')", "!query.isOrderByChild(auth.uid)", "!query.isOrderByChild('\\uD83D')", "query.isOrderByChild()",
  "query.isOrderByChild(1)", "query.isOrderByChild('a', 'b')", "query.isOrderByChild != null", "query.isOrderByChild('m') == true",
  'query.endBefore == 2', "query.endBefore == 'b'", 'query.endBefore == null', '!(query.endBefore == null)', 'query.endBefore.length == 1',
  'query.endAt == 2', 'query.equalTo == 2', 'query.startAfter == null',
  'query.orderBy == OrderByKey', 'query.orderBy == OrderByValue', 'query.orderBy == OrderByPriority', "query.orderBy == '.priority'",
  "OrderByPriority == '.priority'", 'OrderByKey == OrderByKey', 'OrderByKey == OrderByValue', 'OrderByKey != OrderByValue',
  "OrderByKey == 'a'", 'OrderByKey != null', 'OrderByKey == null', 'OrderByKey.length == 0', "OrderByValue != '.value'",
  'http != null', 'http.foo == null', 'http.encodeURL != null', 'http.encodeURL()', 'http.encodeURL(1)', "http.encodeURL('a', 'b')",
  'http.encodeURL(null) == null', '!(http.encodeURL(auth.missing) == null)', "http.encodeURL('a b') == 'a+b'",
  ...ENCODED.map(([s, e]) => `http.encodeURL('${s}') == '${e}'`),
  'auth.uid.contains != null', 'auth.uid.contains == null', '!(auth.missing.contains == null)', "auth.uid['matches'] != null",
  "(now > 0 ? data.child : 's') != null", "(now > 0 ? data.child : 's') == (now > 0 ? data.child : 's')", "(now > 0 ? 'a'.contains : 's') == 's'",
  'data.child != null', "(now > 0 ? data.child : data.parent)('o').exists()", "(now < 0 ? data.child : data.parent)('o').exists()",
  "!((now < 0 ? data.child : data.parent)('o').exists())", "(now > 0 ? 'abc'.contains : 'abc'.beginsWith)('b')",
  "(now < 0 ? 'abc'.contains : 'abc'.beginsWith)('b')", "(now > 0 ? data.child : 's')('o').exists()", "(data.child)('o').exists()",
  "(now > 0 ? http.encodeURL : 's')('a b') == 'a%20b'", "(now > 0 ? query.isOrderByChild : data.child)('m')",
  "(now > 0 ? data.child : data.parent)().exists()", "now(1) == null", "auth('a') == null", "('a')('b') == null", "(data)('a').exists()",
  "(auth.uid)('a') == null", "(now > 0 ? 'abc' : 's')('b')",
];

const TOKEN = (() => {
  const b64 = s => Buffer.from(s).toString('base64url');
  return `${b64('{"alg":"none","typ":"JWT"}')}.${b64('{"sub":"u1","uid":"u1","iat":1,"exp":9999999999,"email":"A@b.co","admin":true,"n":3,"roles":["x"]}')}.`;
})();
const SEED = { t: { s: 'Hello', n: 5, d: 2.5, b: true, z: 0, o: { k: 'v', m: 1 }, arr: { 0: 'a', 1: 'b' }, '.priority': 7 }, u: 'u1' };

async function main(out) {
  const { host, stop } = await startJar();
  const rows = [];
  try {
    // Each read gets its own namespace: an internal error (500) makes the official emulator's namespace inactive.
    let n = 0;
    const call = (ns, method, path, body, query = '', owner = false) => fetch(`http://${host}${path}?ns=syntax${ns}${query ? `&${query}` : ''}`, { method, headers: owner ? { authorization: 'Bearer owner' } : {}, body });
    for (const expr of EXPRESSIONS) {
      for (const query of QUERIES) {
        const ns = n++;
        await (await call(ns, 'PUT', '/.json', JSON.stringify(SEED), '', true)).text();
        const load = await call(ns, 'PUT', '/.settings/rules.json', JSON.stringify({ rules: { t: { '.read': expr, '.indexOn': INDEX_ON } } }), '', true);
        const loadText = await load.text();
        let read = null;
        if (load.status === 200) {
          const answer = await call(ns, 'GET', '/t.json', undefined, `${query ? `${query}&` : ''}auth=${TOKEN}`);
          await answer.text();
          read = answer.status;
        }
        rows.push({ expr, query, indexOn: INDEX_ON, load: load.status, error: load.status === 200 ? null : JSON.parse(loadText).error, read });
        if (load.status !== 200) break;   // a refused document has one row
      }
    }
  } finally { await stop(); }
  writeFileSync(out, `${JSON.stringify(rows, null, 1)}\n`, { flag: 'wx' });
}

if (process.argv[1]?.endsWith('record_query_syntax.mjs')) main(process.argv[2]).catch(e => { console.error(e.message); process.exitCode = 1; });
