import { readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const versionPattern = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;
const smokeNames = ['storage', 'client', 'auth', 'firestore-listen-transaction', 'functions'];

export function buildCombination({ suite, versions, recordedOn, runId, smokes }) {
  if (!['light', 'broad'].includes(suite)) throw new Error('Invalid suite');
  if (typeof recordedOn !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(recordedOn) ||
      Number.isNaN(Date.parse(`${recordedOn}T00:00:00Z`)) ||
      new Date(`${recordedOn}T00:00:00Z`).toISOString().slice(0, 10) !== recordedOn) {
    throw new Error('Invalid recordedOn date');
  }
  if (runId !== null && (typeof runId !== 'string' || !/^\d+$/.test(runId))) throw new Error('Invalid runId');
  if (!versions || typeof versions !== 'object' || Array.isArray(versions)) throw new Error('Invalid versions');
  for (const name of ['fireemu', 'firebase', 'firebaseAdmin', 'firebaseFunctions']) {
    const value = versions[name];
    if (!(name === 'firebaseFunctions' && value === null) &&
        (typeof value !== 'string' || !versionPattern.test(value))) throw new Error(`Invalid version: ${name}`);
  }
  if (!Array.isArray(smokes) || smokes.length === 0 || new Set(smokes).size !== smokes.length ||
      smokes.some((name) => !smokeNames.includes(name))) throw new Error('Invalid smokes');
  return {
    schemaVersion: 1, suite, recordedOn, runId,
    versions: { fireemu: versions.fireemu, firebase: versions.firebase, firebaseAdmin: versions.firebaseAdmin, firebaseFunctions: versions.firebaseFunctions },
    smokes,
  };
}

export function parseCombination(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some((key) => !['schemaVersion', 'suite', 'recordedOn', 'runId', 'versions', 'smokes'].includes(key)) ||
      value.schemaVersion !== 1) throw new Error('Invalid record');
  if (!value.versions || typeof value.versions !== 'object' || Array.isArray(value.versions) ||
      Object.keys(value.versions).some((key) => !['fireemu', 'firebase', 'firebaseAdmin', 'firebaseFunctions'].includes(key))) {
    throw new Error('Invalid versions');
  }
  buildCombination(value);
  return value;
}

export async function readInstalledVersions(installDir) {
  const versions = {};
  for (const [name, key] of [['fireemu', 'fireemu'], ['firebase', 'firebase'], ['firebase-admin', 'firebaseAdmin'], ['firebase-functions', 'firebaseFunctions']]) {
    try {
      versions[key] = JSON.parse(await readFile(join(installDir, 'node_modules', name, 'package.json'), 'utf8')).version;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      if (name === 'firebase-functions') versions[key] = null;
      else throw new Error(`Missing package: ${name}`);
    }
  }
  return versions;
}

export async function main(argv) {
  const values = { smokes: [], runId: null, recordedOn: new Date().toISOString().slice(0, 10) };
  const flags = { '--suite': 'suite', '--install-dir': 'installDir', '--out': 'out', '--smoke': 'smokes', '--run-id': 'runId', '--date': 'recordedOn' };
  for (let i = 0; i < argv.length; i++) {
    const key = flags[argv[i]];
    if (!key) throw new Error(`Unknown flag: ${argv[i]}`);
    const value = argv[++i];
    if (value === undefined || value.startsWith('--')) throw new Error(`Missing value for ${argv[i - 1]}`);
    if (key === 'smokes') values.smokes.push(value);
    else values[key] = value;
  }
  if (!values.suite || !values.installDir || !values.out) throw new Error('Missing required flag');
  const versions = await readInstalledVersions(values.installDir);
  const record = buildCombination({ ...values, versions });
  await writeFile(values.out, `${JSON.stringify(record, null, 2)}\n`, { flag: 'wx' });
  return record;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(() => {
    console.log(process.argv[process.argv.indexOf('--out') + 1]);
  }).catch((error) => {
    console.error(String(error.message).replace(/[\r\n]+/g, ' '));
    process.exitCode = 1;
  });
}
