// Runs the Realtime Database smokes against one server and compares them with the
// recording of the official emulator (firebase-database-emulator v4.11.2) in fixtures/.
//
//   node run.mjs [--host <host:port>] [--only crud,listen,queries,long-polling]
//                [--record <dir>] [--expect <dir>]
//
// The host defaults to FIREBASE_DATABASE_EMULATOR_HOST, so that
//   fireemu exec --only database -- node tools/sdk-smoke-database/run.mjs
// needs no configuration. --record writes each smoke's events instead of comparing them
// (that is how the fixtures were made, against the official emulator).

import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { crud, listen, queries } from './smokes.mjs';
import { firstDifference } from './compare.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const option = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const host = option('--host') ?? process.env.FIREBASE_DATABASE_EMULATOR_HOST;
if (!host) {
  console.error('run.mjs: give --host <host:port> or set FIREBASE_DATABASE_EMULATOR_HOST');
  process.exit(2);
}
const record = option('--record');
const expect = option('--expect') ?? path.join(here, 'fixtures', 'official-emulator-4.11.2');
const smokes = {
  crud,
  listen,
  queries,
  'long-polling': async (h, s) => (await import('./long-polling.mjs')).longPolling(h, s),
};
const selected = (option('--only') ?? Object.keys(smokes).join(',')).split(',');
const suffix = Date.now().toString(36);
let failed = 0;
for (const name of selected) {
  const smoke = smokes[name];
  if (!smoke) {
    console.error(`run.mjs: unknown smoke ${name}`);
    process.exit(2);
  }
  const result = await smoke(host, suffix);
  if (record) {
    mkdirSync(record, { recursive: true });
    writeFileSync(path.join(record, `${name}.json`), `${JSON.stringify(result, null, 1)}\n`);
    console.log(`${name}: recorded`);
    continue;
  }
  const file = path.join(expect, `${name}.json`);
  if (!existsSync(file)) {
    console.error(`${name}: no recording at ${file}`);
    failed += 1;
    continue;
  }
  const difference = firstDifference(JSON.parse(readFileSync(file, 'utf8')), result);
  if (difference) {
    console.log(`${name}: differs from the official emulator: ${difference}`);
    failed += 1;
  } else {
    console.log(`${name}: same as the official emulator`);
  }
}
process.exit(failed ? 1 : 0);
