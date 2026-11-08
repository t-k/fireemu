import { createRequire } from 'node:module';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '../../../..');
const require = createRequire(import.meta.url);
const { listFiles } = require(join(repo, 'conformance/node_modules/firebase-tools/lib/listFiles.js'));
const fixture = join(here, 'deploy-ignore-fixture.json');
const rows = JSON.parse(readFileSync(fixture, 'utf8'));
const extra = [
  ['private.json/**', 'private.json'],
  ['private.json/', 'private.json'],
  ['{./private.json,public.json}', 'private.json'],
  ['{PUBLIC_ROOT}/private.json', 'private.json'],
  ['PRIVATE.JSON', 'private.json', true],
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
  ['[A-Z]*.json', 'private.json', true],
];
for (const [pattern, path, nocase] of extra) {
  if (!rows.some(row => row.pattern === pattern && row.path === path)) {
    rows.push({ pattern, path, ...(nocase && { nocase: true }) });
  }
}
const tempBase = join(repo, 'target/codex-out');
mkdirSync(tempBase, { recursive: true });
const root = mkdtempSync(join(tempBase, 'deploy-ignore-'));
try {
  for (const path of new Set(rows.map(row => row.path))) {
    const file = join(root, path);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, 'fixture');
  }
  for (const pattern of new Set(rows.map(row => row.pattern))) {
    const listed = new Set(listFiles(root, [pattern.replace('{PUBLIC_ROOT}', root)]));
    for (const row of rows.filter(row => row.pattern === pattern)) {
      row.expected = !listed.has(row.path);
      delete row.generated_on;
    }
  }
  rows[0].generated_on = process.platform;
  writeFileSync(fixture, JSON.stringify(rows, null, 2) + '\n');
} finally {
  rmSync(root, { recursive: true, force: true });
}
