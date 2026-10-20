import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { JAR_SHA256, sha256, verifyJar } from './jar.mjs';

test('a file is hashed with SHA-256', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'jar-test-'));
  const file = path.join(dir, 'f');
  writeFileSync(file, 'abc');
  assert.equal(await sha256(file), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('a jar that is not the pinned one is refused', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'jar-test-'));
  const file = path.join(dir, 'fake.jar');
  writeFileSync(file, 'not the emulator');
  await assert.rejects(verifyJar(file), /not the pinned b70d9934/);
  await verifyJar(file, await sha256(file));
  assert.equal(JAR_SHA256.length, 64);
});
