// Runs the Realtime Database smokes against one server and compares them with the
// recording of the official emulator (firebase-database-emulator v4.11.2) in fixtures/.
//
//   node run.mjs [--host <host:port>] [--only crud,listen,queries,disconnect,long-polling]
//                [--expect <dir>]
//   node run.mjs --record <dir> [--jar <path>] [--only ...]
//
// The host defaults to FIREBASE_DATABASE_EMULATOR_HOST, so that
//   fireemu exec --only database -- node tools/sdk-smoke-database/run.mjs
// needs no configuration. --record writes each smoke's events instead of comparing them, and
// records only the official emulator: it checks the jar's SHA-256 against the pinned one
// (jar.mjs) and starts it on a free port itself, so --host does not go with it.

import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { crud, disconnect, listen, queries } from './smokes.mjs';
import { firstDifference } from './compare.mjs';
import { DEFAULT_JAR, startJar } from './jar.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const option = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const record = option('--record');
if (record && option('--host')) {
  console.error('run.mjs: --record starts the pinned official emulator itself; drop --host');
  process.exit(2);
}
const smokes = {
  crud,
  listen,
  queries,
  disconnect,
  'long-polling': async (h, s) => (await import('./long-polling.mjs')).longPolling(h, s),
};
const selected = (option('--only') ?? Object.keys(smokes).join(',')).split(',');
// Every name is checked before anything starts, so a typo leaves nothing running.
const unknown = selected.filter((name) => !smokes[name]);
if (unknown.length) {
  console.error(`run.mjs: unknown smoke ${unknown.join(', ')}`);
  process.exit(2);
}
let jar;
if (record) {
  try {
    jar = await startJar(option('--jar') ?? DEFAULT_JAR);
  } catch (e) {
    console.error(`run.mjs: ${e.message}`);
    process.exit(2);
  }
}
// The jar stops however the run ends: a smoke that throws, or Ctrl-C.
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, async () => {
    await jar?.stop();
    process.exit(130);
  });
}
let failed = 0;
try {
  const host = jar?.host ?? option('--host') ?? process.env.FIREBASE_DATABASE_EMULATOR_HOST;
  if (!host) {
    console.error('run.mjs: give --host <host:port> or set FIREBASE_DATABASE_EMULATOR_HOST');
    process.exitCode = 2;
  } else {
    const expect = option('--expect') ?? path.join(here, 'fixtures', 'official-emulator-4.11.2');
    const suffix = Date.now().toString(36);
    for (const name of selected) {
      const result = await smokes[name](host, suffix);
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
  }
} finally {
  await jar?.stop();
}
process.exit(process.exitCode ?? (failed ? 1 : 0));
