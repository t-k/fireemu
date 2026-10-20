// The official database emulator the recordings come from: firebase-database-emulator v4.11.2,
// the jar firebase-tools 15.28.2 downloads (`firebase setup:emulators:database`), pinned by its
// SHA-256 (the same value as spec/compatibility/contract.json baseline.bundledEmulators).
// Recording runs only against this jar, started here on a free loopback port.

import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { createServer } from 'node:net';
import { homedir } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

/** Every jar started here and not yet stopped, so a signal can stop one still starting. */
const started = new Set();

/** Stops every jar started here. */
export async function stopStarted() {
  await Promise.all([...started].map((stop) => stop()));
}

export const JAR_SHA256 = 'b70d99344caf17c98b6f910fa8f6edf32a7c016cb1035e8915f70d38901eb97f';
export const DEFAULT_JAR = path.join(homedir(), '.cache', 'firebase', 'emulators', 'firebase-database-emulator-v4.11.2.jar');

/** The SHA-256 of a file, in lowercase hexadecimal. */
export function sha256(file) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    createReadStream(file)
      .on('error', reject)
      .on('data', (chunk) => hash.update(chunk))
      .on('end', () => resolve(hash.digest('hex')));
  });
}

/** Refuses a jar whose SHA-256 is not the pinned one. */
export async function verifyJar(file, expected = JAR_SHA256) {
  const actual = await sha256(file);
  if (actual !== expected) {
    throw new Error(`${file} has SHA-256 ${actual}, not the pinned ${expected}; fetch it with firebase-tools 15.28.2 (npx firebase-tools@15.28.2 setup:emulators:database)`);
  }
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

/** Starts the verified jar on a free loopback port; returns its host:port and a stop function. */
export async function startJar(file = DEFAULT_JAR) {
  await verifyJar(file);
  const port = await freePort();
  const child = spawn('java', ['-Duser.language=en', '-jar', file, '--port', String(port), '--host', '127.0.0.1'], { stdio: 'ignore' });
  const host = `127.0.0.1:${port}`;
  const stop = () => new Promise((resolve) => {
    started.delete(stop);
    if (child.exitCode !== null) return resolve();
    child.once('exit', () => resolve());
    child.kill('SIGTERM');
  });
  started.add(stop);
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`the jar exited with ${child.exitCode}`);
    try {
      const res = await fetch(`http://${host}/.json?ns=ready`);
      if (res.ok) return { host, stop };
    } catch {
      // Not listening yet.
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  await stop();
  throw new Error('the jar did not answer within 20 s');
}
