import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// `expected` is what glob's Ignore does where matching is case-insensitive (macOS, Windows);
// `caseSensitive` is added only for the rows where it differs on Linux. Both come from a worker
// that pins process.platform before glob loads, so the result does not depend on the host.
const worker = process.argv[2] === '--worker';
const tempBase = tmpdir();
if (worker) Object.defineProperty(process, 'platform', { value: process.argv[3] });

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '../../../..');
const require = createRequire(import.meta.url);
// The pinned oracle is firebase-tools 15.28.2 as `npm install` resolves it (glob ^10.5.0). The
// conformance lockfile can pin a different glob, so FIREEMU_LIST_FILES may name another listFiles.js.
const { listFiles } = require(
  process.env.FIREEMU_LIST_FILES ?? join(repo, 'conformance/node_modules/firebase-tools/lib/listFiles.js'),
);
const fixture = join(here, 'deploy-ignore-fixture.json');
const rows = JSON.parse(readFileSync(fixture, 'utf8'));
const extra = [
  ['private.json/**', 'private.json'],
  ['private.json/', 'private.json'],
  ['{./private.json,public.json}', 'private.json'],
  ['{PUBLIC_ROOT}/private.json', 'private.json'],
  ['PRIVATE.JSON', 'private.json'],
  ['\\{private\\,public\\}.json', 'private.json'],
  ['\\{private\\,public\\}.json', 'public.json'],
  ['private\\,public.json', 'private,public.json'],
  ['\\{private\\,public\\}\\.json', 'private.json'],
  ['{private,public}\\*.json', 'private*.json'],
  ['{private,public}\\*.json', 'private.json'],
  ['private\\*.json', 'private*.json'],
  ['private\\*.json', 'private.json'],
  ['[A-z]*.json', '_secret.json'],
  ['[A-z]*.json', 'Private.json'],
  ['[a-Z]*.json', '_secret.json'],
  ['[^A-z]*.json', '_secret.json'],
  ['[^A-z]*.json', '0secret.json'],
  ['[A-Z]*.json', 'private.json'],
];
// Unicode case folding under nocase: glob 10.5.0 compiles each segment to a JavaScript regex with the
// `i` flag (no `u` flag), so a character folds only through toUpperCase() when that is one UTF-16
// unit and does not map a non-ASCII character to ASCII. `fold` is the partner a simple case folding
// or a case mapping would pair with the subject; the probes show which of them the oracle accepts.
// Every row has its own stem so that no two paths differ only by case or normalization.
const subjects = {
  ascii: ['s', 'S', 'S'],
  'sharp-s': ['\u00df', 'SS', '\u1e9e'],
  'long-s': ['\u017f', 'S', 's'],
  kelvin: ['\u212a', 'k', 'K'],
  'dotted-I': ['\u0130', 'i', 'i'],
  'dotless-i': ['\u0131', 'I', 'i'],
  'final-sigma': ['\u03c2', '\u03a3', '\u03c3'],
  'titlecase-dz': ['\u01c5', '\u01c6', '\u01c4'],
  'latin1-accent': ['\u00e9', '\u00c9', '\u00c9'],
};
const shapes = {
  literal: (c) => c,
  class: (c) => `[${c}]`,
  negclass: (c) => `[^${c}]`,
  range: (c) => `[${c}-${c}]`,
  negrange: (c) => `[^${c}-${c}]`,
};
let unicodeRow = 0;
for (const [, [subject, other, fold]] of Object.entries(subjects)) {
  for (const shape of Object.values(shapes)) {
    for (const probe of [subject, other, fold]) {
      const stem = `u${String(unicodeRow++).padStart(3, '0')}-`;
      extra.push([`${stem}${shape(subject)}x.json`, `${stem}${probe}x.json`]);
    }
  }
}
for (const [pattern, path] of extra) {
  if (!rows.some(row => row.pattern === pattern && row.path === path)) rows.push({ pattern, path });
}
function exclusions(rows) {
  const root = mkdtempSync(join(tempBase, 'deploy-ignore-'));
  const out = {};
  try {
    for (const path of new Set(rows.map(row => row.path))) {
      const file = join(root, path);
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, 'fixture');
    }
    for (const pattern of new Set(rows.map(row => row.pattern))) {
      const listed = new Set(listFiles(root, [pattern.replace('{PUBLIC_ROOT}', root)]));
      for (const row of rows.filter(row => row.pattern === pattern)) {
        out[JSON.stringify([row.pattern, row.path])] = !listed.has(row.path);
      }
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  return out;
}

if (worker) {
  process.stdout.write(JSON.stringify(exclusions(rows)));
} else {
  const run = platform =>
    JSON.parse(
      execFileSync(process.execPath, [fileURLToPath(import.meta.url), '--worker', platform], {
        env: process.env,
        maxBuffer: 1 << 28,
      }),
    );
  const nocase = run('darwin');
  const sensitive = run('linux');
  for (const row of rows) {
    const key = JSON.stringify([row.pattern, row.path]);
    delete row.nocase;
    delete row.caseSensitive;
    delete row.generated_on;
    row.expected = nocase[key];
    if (sensitive[key] !== nocase[key]) row.caseSensitive = sensitive[key];
  }
  rows[0].generated_on = process.platform;
  writeFileSync(fixture, JSON.stringify(rows, null, 2) + '\n');
}
