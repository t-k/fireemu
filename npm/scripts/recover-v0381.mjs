export function decide(status, integrityMatches, provenanceMatches) {
  if (status === 'missing') return 'publish';
  if (status === 'present' && integrityMatches && provenanceMatches) return 'skip';
  throw new Error('registry state is not safe for recovery');
}

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SHA = '24122ce3e375323da91290de11d01b45d14aa9a5';
const REPO = 't-k/fireemu';
const RUN = '40986239359';
const VERSION = '0.38.1';
const ARTIFACTS = {
  'package-darwin-arm64': [12948337818, '14f2fd567166424f1a93013e46cb28402087c034c77fd9806c68abe64e1127f9'],
  'package-darwin-x64': [12948362745, '281353c9230919bb4a71b0f33c0a9a6aaa4466b6b0646afa25c2c5a673f51d72'],
  'package-linux-arm64': [12948721282, 'ccbd0913ac4cbb28e793fda948ce2a0b9614bf5179208244320e6c272da6331b'],
  'package-linux-x64': [12948826060, '65e371af878d67ba088b9336b1895e702848f13db29ac423b7c396e9376aa238'],
  'package-win32-x64': [12949206050, '6f7f5397a54b12915ae10db9c597654649802cad19238ca1d03967de1e0a03ad'],
  'release-assets': [12950892885, '29682c546332242c97341c8dc8b8de30582611ce1fe5fea5c2007eaca04f1850'],
  'release-notes': [12947331305, '2ecfd01e7b2afd11b2d0e0533be7b0c2a004424e8247c115efc18052609e3ca9'],
};
const PLATFORMS = Object.keys(ARTIFACTS).filter(x => x.startsWith('package-')).map(x => x.slice(8));
export function childEnvironment(cmd, args, source) {
  const env = { ...source };
  if (cmd !== 'gh') delete env.GH_TOKEN;
  if (cmd !== 'npm' || args[0] !== 'publish') {
    delete env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    delete env.ACTIONS_ID_TOKEN_REQUEST_URL;
  }
  return env;
}
const invoke = (cmd, args, options = {}) => execFileSync(cmd, args, { stdio: ['ignore', 'pipe', 'inherit'], maxBuffer: 256 * 1024 * 1024, env: childEnvironment(cmd, args, process.env), ...options });
const json = (cmd, args, options) => JSON.parse(invoke(cmd, args, options));
const hash = (algorithm, bytes, encoding = 'hex') => createHash(algorithm).update(bytes).digest(encoding);
const api = path => json('gh', ['api', `repos/${REPO}/${path}`]);
const fail = message => { throw new Error(message); };

function checkOrigin() {
  if (process.env.GITHUB_REPOSITORY !== REPO || process.env.GITHUB_EVENT_NAME !== 'workflow_dispatch' || process.env.GITHUB_REF !== 'refs/heads/main' || !process.env.GITHUB_WORKFLOW_REF?.startsWith(`${REPO}/.github/workflows/release.yml@`)) fail('unexpected recovery identity');
  const run = api(`actions/runs/${RUN}`);
  if (run.head_sha !== SHA || run.head_branch !== `v${VERSION}` || run.event !== 'push' || run.status !== 'completed' || run.conclusion !== 'failure') fail('unexpected source run');
  const ref = api(`git/ref/tags/v${VERSION}`);
  let target = ref.object;
  if (target.type === 'tag') target = api(`git/tags/${target.sha}`).object;
  if (target.type !== 'commit' || target.sha !== SHA) fail('tag has changed');
  const jobs = api(`actions/runs/${RUN}/attempts/1/jobs?per_page=100`).jobs;
  for (const job of ['plan', 'ui', 'test', 'reproducible', 'verify-artifact', 'strict-production']) {
    if (!jobs.some(x => x.name === job && x.conclusion === 'success')) fail(`missing successful ${job}`);
  }
  for (const platform of PLATFORMS) if (!jobs.some(x => x.name.startsWith(`build (${platform},`) && x.conclusion === 'success')) fail(`missing successful build ${platform}`);
}

function download(name, dir) {
  const [id, digest] = ARTIFACTS[name];
  const bytes = invoke('gh', ['api', `repos/${REPO}/actions/artifacts/${id}/zip`]);
  if (hash('sha256', bytes) !== digest) fail(`artifact digest mismatch: ${name}`);
  const zip = join(dir, `${name}.zip`);
  const out = join(dir, name);
  writeFileSync(zip, bytes); mkdirSync(out);
  invoke('unzip', ['-q', zip, '-d', out]);
  return out;
}

function verifyAttestation(path) {
  invoke('gh', ['attestation', 'verify', path, '--repo', REPO, '--signer-workflow', `${REPO}/.github/workflows/release.yml`, '--source-digest', SHA, '--source-ref', `refs/tags/v${VERSION}`]);
}

function pack(path, dir) {
  const [result] = json('npm', ['pack', path, '--pack-destination', dir, '--json']);
  return { path: join(dir, result.filename), integrity: result.integrity };
}

export async function registry(name) {
  const response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}/${VERSION}`, { redirect: 'error' });
  if (response.status === 404) return null;
  if (!response.ok) fail(`registry ${name}: HTTP ${response.status}`);
  const metadata = await response.json();
  if (metadata.name !== name || metadata.version !== VERSION || typeof metadata.dist?.integrity !== 'string') fail('unexpected registry metadata');
  return metadata;
}

async function verifyPresent(name, expected, metadata, dir, allowedShas) {
  if (metadata.dist.integrity !== expected.integrity) fail(`registry integrity mismatch: ${name}`);
  const url = new URL(metadata.dist.tarball);
  if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org') fail('unexpected tarball URL');
  const response = await fetch(url, { redirect: 'error' });
  if (!response.ok) fail(`tarball HTTP ${response.status}`);
  const tarball = Buffer.from(await response.arrayBuffer());
  if (`sha512-${hash('sha512', tarball, 'base64')}` !== expected.integrity) fail(`tarball digest mismatch: ${name}`);
  const audit = join(dir, `audit-${name.replace(/[^a-z0-9]/g, '-')}`);
  mkdirSync(audit);
  writeFileSync(join(audit, 'package.json'), JSON.stringify({ name: 'recovery-audit', version: '1.0.0', private: true }));
  invoke('npm', ['install', '--prefix', audit, '--ignore-scripts', '--no-audit', '--no-fund', '--force', `${name}@${VERSION}`]);
  const result = json('npx', ['--yes', 'npm@12.2.1', 'audit', 'signatures', '--prefix', audit, '--json', '--include-attestations']);
  const entry = result.verified?.find(x => x.name === name && x.version === VERSION);
  const provenance = entry?.attestationBundles?.find(x => x.predicateType === 'https://slsa.dev/provenance/v1');
  if (!provenance) fail(`no verified provenance: ${name}`);
  const statement = JSON.parse(Buffer.from(provenance.bundle.dsseEnvelope.payload, 'base64').toString());
  if (!allowedShas.some(sha => validateProvenance(statement, name, expected.integrity, sha))) fail(`provenance mismatch: ${name}`);
}

export function validateProvenance(statement, name, integrity, expectedSha) {
  if (!integrity.startsWith('sha512-')) return false;
  const digest = Buffer.from(integrity.slice(7), 'base64').toString('hex');
  const workflow = statement.predicate?.buildDefinition?.externalParameters?.workflow;
  const deps = statement.predicate?.buildDefinition?.resolvedDependencies;
  const invocation = statement.predicate?.runDetails?.metadata?.invocationId;
  const pattern = expectedSha === SHA ? /^https:\/\/github\.com\/t-k\/fireemu\/actions\/runs\/40986239359\/attempts\/1$/ : /^https:\/\/github\.com\/t-k\/fireemu\/actions\/runs\/\d+\/attempts\/\d+$/;
  return Boolean(typeof invocation === 'string' && pattern.test(invocation) && statement.subject?.some(x => x.name === `pkg:npm/${name.replace('@', '%40')}@${VERSION}` && x.digest?.sha512 === digest) && workflow?.ref === (expectedSha === SHA ? `refs/tags/v${VERSION}` : 'refs/heads/main') && workflow?.repository === `https://github.com/${REPO}` && workflow?.path === '.github/workflows/release.yml' && deps?.some(x => x.digest?.gitCommit === expectedSha));
}

export async function publishAll(packages, operations, preflight = false) {
  const initial = new Map();
  for (const [name, expected] of packages) {
    const metadata = await operations.lookup(name);
    if (metadata) await operations.verify(name, expected, metadata);
    initial.set(name, decide(metadata ? 'present' : 'missing', true, true));
  }
  if (preflight) return;
  for (const [name, expected] of packages) {
    if (initial.get(name) === 'skip') { console.log(`verified existing ${name}@${VERSION}`); continue; }
    await operations.publish(name, expected);
    await operations.verifyPublished(name, expected);
  }
}

async function main() {
  checkOrigin();
  const source = resolve('recovery-source');
  if (invoke('git', ['rev-parse', 'HEAD'], { cwd: source, encoding: 'utf8' }).trim() !== SHA) fail('source checkout mismatch');
  const dir = mkdtempSync(join(process.env.RUNNER_TEMP || tmpdir(), 'v0381-recovery-'));
  const output = resolve('recovery-output');
  mkdirSync(output, { recursive: true });
  try {
    const assets = download('release-assets', dir);
    const notes = download('release-notes', dir);
    invoke('sha256sum', ['--check', 'SHA256SUMS'], { cwd: assets });
    for (const file of readdirSync(assets).filter(x => x.startsWith('fireemu-'))) verifyAttestation(join(assets, file));
    const tarballs = new Map();
    for (const platform of PLATFORMS) {
      const pkg = download(`package-${platform}`, dir);
      const archive = join(assets, `fireemu-${VERSION}-${platform}.${platform.startsWith('win32') ? 'zip' : 'tar.gz'}`);
      const extracted = join(dir, `archive-${platform}`); mkdirSync(extracted);
      if (platform.startsWith('win32')) invoke('unzip', ['-q', archive, '-d', extracted]);
      else invoke('tar', ['-xzf', archive, '-C', extracted]);
      invoke('diff', ['-rq', pkg, join(extracted, platform)]);
      invoke('find', [pkg, '-type', 'f', '-exec', 'chmod', '644', '{}', '+']);
      tarballs.set(`@fireemu/${platform}`, pack(pkg, dir));
    }
    invoke('node', ['npm/scripts/stamp-version.mjs', VERSION], { cwd: source });
    invoke('node', ['npm/scripts/prepare-launcher.mjs'], { cwd: source });
    tarballs.set('fireemu', pack(join(source, 'npm/fireemu'), dir));
    const preflight = process.argv.includes('--preflight');
    await publishAll(tarballs, {
      lookup: registry,
      verify: (name, expected, metadata) => verifyPresent(name, expected, metadata, dir, [SHA, process.env.GITHUB_SHA]),
      publish: async (name, expected) => { invoke('npm', ['publish', expected.path, '--provenance', '--access', 'public']); },
      verifyPublished: async (name, expected) => {
        const metadata = await registry(name);
        if (!metadata) fail(`published package absent: ${name}`);
        await verifyPresent(name, expected, metadata, dir, [process.env.GITHUB_SHA]);
      },
    }, preflight);
    if (preflight) { console.log('preflight complete; no packages published'); return; }
    invoke('cp', ['-R', `${assets}/.`, output]);
    invoke('cp', ['-R', `${notes}/.`, output]);
    writeFileSync(join(output, 'recovery-provenance.txt'), `The release binaries were built and tested from ${SHA} in run ${RUN}. The remaining npm packages were published from those artifacts by the recovery workflow. Recovery completion run ${process.env.GITHUB_RUN_ID} used workflow SHA ${process.env.GITHUB_SHA}. Each package’s npm provenance identifies its actual publishing run; recovered packages reference recovery runs rather than the original build run.\n`);
    console.log(`Original build: ${SHA}, run ${RUN}; recovery publish: ${process.env.GITHUB_SHA}, run ${process.env.GITHUB_RUN_ID}.`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error); process.exitCode = 1; });
}
