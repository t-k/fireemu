// Private, append-only lifecycle checkpoints. These are recovery responsibility
// records, NOT proof of absence or authority to delete after a restart.
import { constants, openSync, closeSync, writeFileSync, fsyncSync, lstatSync,
  readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { ownedPaths, secondaryPaths } from './listen_collector.mjs';

const phases = ['ready', 'account-create-intent', 'account-created',
  'documents-at-risk', 'lifecycle-result'];
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const sameKeys = (v, keys) => object(v) && JSON.stringify(Object.keys(v).sort()) ===
  JSON.stringify([...keys].sort());

/** The supervisor creates a fresh private directory before launching the SDK.
 * Failure is synchronous: never begin signup/document traffic without its
 * corresponding durable responsibility record. Raw tokens/passwords are not
 * accepted by this deliberately small schema.
 */
export function createLifecycleJournal(directory, { nonce, projectId }) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory) ||
      !/^[0-9a-f]{32}$/.test(nonce) || !/^[a-zA-Z0-9_-]{1,128}$/.test(projectId)) {
    throw new Error('invalid private lifecycle journal');
  }
  const info = lstatSync(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o077) !== 0 ||
      readdirSync(directory).length !== 0) throw new Error('fresh private journal required');
  let previous = null;
  let last = -1;
  let failed = false;
  const writeCheckpoint = (phase, value = {}) => {
    const index = phases.indexOf(phase);
    if (index < 0 || index <= last || (last < 0 && index !== 0) ||
        (index === 2 && last !== 1) || (index === 3 && last !== 2)) {
      throw new Error('invalid lifecycle checkpoint order');
    }
    if (phase === 'account-created') {
      // One principal, or two: the second principal's uid and its single owned
      // path are recorded in the same checkpoint so recovery knows both.
      const safeUid = uid => typeof uid === 'string' && uid.length > 0 && uid.length <= 128 &&
        !/[\x00-\x1f\x7f/]/.test(uid);
      const two = sameKeys(value, ['uid', 'paths', 'secondaryUid', 'secondaryPaths']);
      if ((!two && !sameKeys(value, ['uid', 'paths'])) || !safeUid(value.uid) ||
          !isDeepStrictEqual(value.paths, ownedPaths(nonce, value.uid)) ||
          (two && (!safeUid(value.secondaryUid) || value.secondaryUid === value.uid ||
            !isDeepStrictEqual(value.secondaryPaths, secondaryPaths(nonce, value.secondaryUid))))) {
        throw new Error('invalid account checkpoint');
      }
    } else if (phase === 'lifecycle-result') {
      if (!sameKeys(value, ['complete', 'accountCleanupComplete',
        'clientsComplete', 'documentsCleanupComplete']) ||
          !Object.values(value).every(v => typeof v === 'boolean')) {
        throw new Error('invalid lifecycle result checkpoint');
      }
      // A success checkpoint requires the complete operation prefix as well as
      // resource/client cleanup. A failed run may still have fully recovered.
      if (value.complete && (last !== 3 || !Object.values(value).every(Boolean))) {
        throw new Error('contradictory lifecycle completion');
      }
    } else if (!sameKeys(value, [])) throw new Error('unexpected lifecycle checkpoint field');
    const raw = Buffer.from(JSON.stringify({ schema: 'local-listen-checkpoint-v1',
      phase, nonce, projectId, accountEmail: `o6-${nonce}@example.test`,
      previousSha256: previous, authorizesCleanup: false, value }) + '\n');
    const fd = openSync(path.join(directory, `${index}-${phase}.json`),
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { writeFileSync(fd, raw); fsyncSync(fd); } finally { closeSync(fd); }
    const dir = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { fsyncSync(dir); } finally { closeSync(dir); }
    previous = createHash('sha256').update(raw).digest('hex');
    last = index;
  };
  const checkpoint = (phase, value = {}) => {
    if (failed) throw new Error('lifecycle journal failure latched');
    try { writeCheckpoint(phase, value); }
    catch { failed = true; throw new Error('lifecycle checkpoint failed'); }
  };
  checkpoint('ready');
  return checkpoint;
}
