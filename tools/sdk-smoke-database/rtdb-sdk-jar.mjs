// Runs a plain-HTTP suite of the RTDB SDK observer (rest, rules, tokens, rules-load) against the pinned official emulator jar
// and reduces the journal the way the suite's local entry does, so the emulator profile can be compared with the jar.
//
//   node rtdb-sdk-jar.mjs <suite> --out <new dir> [--timeout <ms>]
//
// The command is the one `fireemu exec` would run (the suite entry's execPlan), started with FIREBASE_DATABASE_EMULATOR_HOST
// naming the jar. Outputs in <out>: observer/ (journal.jsonl, result.json) and journal.json. Exit status: the observer's.
import { mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { startJar } from './jar.mjs';

export const SUITES = {
  rest: () => import('./rtdb-sdk-rest.mjs'),
  rules: () => import('./rtdb-sdk-rules.mjs'),
  tokens: () => import('./rtdb-sdk-tokens.mjs'),
  'rules-load': () => import('./rtdb-sdk-rules-load.mjs'),
};

export function parse(argv) {
  const [suite, ...rest] = argv, opt = n => { const i = rest.indexOf(n); return i >= 0 ? rest[i + 1] : undefined; };
  if (!Object.hasOwn(SUITES, suite ?? '')) throw Error(`usage: <${Object.keys(SUITES).join('|')}> --out <new dir> [--timeout <ms>]`);
  if (!opt('--out')) throw Error('--out is required');
  return { suite, out: path.resolve(opt('--out')), timeout: Number(opt('--timeout') ?? 9 * 60 * 1000) };
}

/** `deps` replaces the jar, the child process and the suite entries in tests. */
export async function run({ suite, out, timeout }, deps = {}) {
  const start = deps.startJar ?? startJar, spawn = deps.spawnSync ?? spawnSync;
  const mod = await (deps.suites ?? SUITES)[suite]();
  mkdirSync(out);   // refuses an existing directory
  const { host, stop } = await start();
  try {
    const plan = mod.execPlan('unused', path.join(out, 'config.json'), path.join(out, 'observer'), `JAR-${suite.toUpperCase()}-01`);
    const command = plan.slice(plan.indexOf('--') + 1);
    const child = spawn(command[0], command.slice(1), { env: { ...process.env, FIREBASE_DATABASE_EMULATOR_HOST: host }, encoding: 'utf8', timeout });
    if (child.error) throw child.error;
    mod.finish(out);
    return child.status;
  } finally { await stop(); }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  run(parse(process.argv.slice(2))).then(code => { process.exitCode = code; }, e => { console.error(`rtdb-sdk-jar: ${e.message}`); process.exitCode = 2; });
}
