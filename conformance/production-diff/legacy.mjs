// Reuse the existing program, session and comparison code without importing run.mjs's
// production acquisition / official-emulator registry. This pinned extraction bridge is
// intentionally temporary: replace with a pure upstream export after its owner agrees.
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promises as fs } from 'node:fs';
import { CASE } from './registry.mjs';
import { blobSha, sha256, requireThat, validateProgram, selectProduction, digestJson } from './core.mjs';
import { readSource, git, gitState, publish } from './io.mjs';

const ADAPTER_DIR = dirname(fileURLToPath(import.meta.url));
const ADAPTER_FILES = ['registry.mjs', 'core.mjs', 'io.mjs', 'legacy.mjs', 'local-session.mjs', 'network.mjs', 'pilot.mjs'];
export async function adapterSourceDigests() {
  const hashes = {};
  for (const name of ADAPTER_FILES) hashes[name] = sha256(await readSource(ADAPTER_DIR, name));
  return hashes;
}

const block = (text, start, end) => {
  const at = text.indexOf(start);
  requireThat(at >= 0 && text.indexOf(start, at + start.length) === -1, 'comparator-anchor');
  const stop = text.indexOf(end, at + start.length);
  requireThat(stop > at, 'comparator-anchor');
  return text.slice(at, stop).trim();
};
export function comparatorModuleSource(text) {
  return 'const PROGRAMS = [];\n' + [
    block(text, 'function decision(step) {', '/** The first path'),
    block(text, 'function canonical(value) {', '/** A transport result'),
    block(text, 'function isCompletedHttpObservation(step) {', '/** Compare saved production'),
    block(text, 'export function compareProductionToFireemu(', 'const rowKey ='),
  ].join('\n\n');
}
export const importText = text => import('data:text/javascript;base64,' + Buffer.from(text).toString('base64'));
export const pin = (bytes, expected) => { requireThat(blobSha(bytes) === expected, 'source-pin-mismatch'); return bytes; };

export async function prepare(repo, entry = CASE) {
  const state = gitState(repo);
  const matrixBytes = pin(await readSource(repo, entry.matrixPath), entry.matrixBlob);
  const matrix = JSON.parse(matrixBytes);
  const production = selectProduction(matrix, entry);
  const corpusBytes = pin(git(repo, ['show', `${entry.observedSource}:${entry.corpusPath}`]), entry.corpusBlob);
  const { PROGRAMS } = await importText(corpusBytes.toString('utf8'));
  requireThat(Array.isArray(PROGRAMS) && 'sha256-' + sha256(JSON.stringify(PROGRAMS)) === entry.corpusDigest,
    'historical-corpus-digest');
  const matches = PROGRAMS.filter(p => p.id === entry.programId);
  requireThat(matches.length === 1, 'historical-program-not-unique');
  const program = validateProgram(matches[0], entry);
  const comparatorBytes = await readSource(repo, entry.comparatorPath);
  const sessionBytes = pin(await readSource(repo, entry.sessionPath), entry.sessionBlob);
  const credentialsBytes = pin(await readSource(repo, entry.credentialsPath), entry.credentialsBlob);
  // Normalization/session bytes are identical to those at the production observation source.
  pin(git(repo, ['show', `${entry.observedSource}:${entry.sessionPath}`]), entry.sessionBlob);
  pin(git(repo, ['show', `${entry.observedSource}:${entry.credentialsPath}`]), entry.credentialsBlob);
  const pure = comparatorModuleSource(comparatorBytes.toString('utf8'));
  requireThat(sha256(pure) === entry.comparatorSliceSha256, 'comparator-semantics-pin-mismatch');
  const { compareProductionToFireemu: comparator } = await importText(pure);
  return { entry, state, program, production, comparator, sessionBytes, credentialsBytes,
    provenance: {
      repository: state, oracle: { path: entry.matrixPath, gitBlob: entry.matrixBlob,
        sha256: sha256(matrixBytes), observedSource: entry.observedSource,
        corpusDigest: entry.corpusDigest, programDigest: digestJson(program),
        projectionDigest: digestJson(production), historicalRawAvailable: false,
        originalCleanupEvidence: 'not-present-in-this-normalized-matrix' },
      implementation: { adapterSha256: await adapterSourceDigests(), comparatorBlob: blobSha(comparatorBytes),
        comparatorSliceSha256: sha256(pure), sessionBlob: entry.sessionBlob,
        credentialsBlob: entry.credentialsBlob },
    } };
}

export async function stageLegacy(prepared, directory) {
  await fs.mkdir(directory, { mode: 0o700 });
  await publish(join(directory, 'session.mjs'), prepared.sessionBytes);
  await publish(join(directory, 'credentials.mjs'), prepared.credentialsBytes);
}

export async function sourceUnchanged(repo, entry, before, adapterBefore) {
  try {
    if (gitState(repo).head !== before.head) return false;
    requireThat(digestJson(await adapterSourceDigests()) === digestJson(adapterBefore), 'adapter-source-changed');
    for (const [path, hash] of [[entry.matrixPath, entry.matrixBlob],
      [entry.sessionPath, entry.sessionBlob],
      [entry.credentialsPath, entry.credentialsBlob]]) pin(await readSource(repo, path), hash);
    requireThat(sha256(comparatorModuleSource((await readSource(repo, entry.comparatorPath)).toString())) ===
      entry.comparatorSliceSha256, 'comparator-changed');
    return true;
  } catch { return false; }
}
