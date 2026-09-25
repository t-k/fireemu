// File-based authority entry. The separate kernel never grants acquisition authority.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

export const compareSavedStreamFilesV2 = ({ root, output, python = 'python3' }) => {
  if (typeof root !== 'string' || typeof output !== 'string') throw new TypeError('root and exclusive output paths required');
  const result = spawnSync(python, [fileURLToPath(new URL('./saved_authority.py', import.meta.url)), '--root', root, '--output', output], { stdio: 'inherit' });
  if (result.error) throw result.error;
  return result.status;
};

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [root, output] = process.argv.slice(2);
  process.exitCode = compareSavedStreamFilesV2({ root, output });
}
