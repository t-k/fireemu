// Resolve package-local optional platform dependencies without starting the CLI.
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { accessSync, chmodSync, constants } from 'node:fs';
const require = createRequire(import.meta.url);
export function resolveBinary(override = process.env.FIREEMU_BINARY_PATH) {
  if (override) return {path:override,from:'FIREEMU_BINARY_PATH'};
  const name = `@fireemu/${process.platform}-${process.arch}`;
  try { return {path:join(dirname(require.resolve(`${name}/package.json`)),'bin',process.platform==='win32'?'fireemu.exe':'fireemu'),from:name}; }
  catch { return undefined; }
}
export function ensureExecutable(path) {
  if(process.platform==='win32')return;
  try {accessSync(path,constants.X_OK);} catch {try{chmodSync(path,0o755);}catch{/* Spawn reports the actionable failure. */}}
}
