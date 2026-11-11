import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { dumpPaths } from '../fireemu/testing.mjs';

test('dump paths name both bundle files in the requested directory', () => {
  const directory = join('reports', 'diagnostics');
  assert.deepEqual(dumpPaths(directory), {
    json: join(directory, 'bundle.json'),
    html: join(directory, 'bundle.html'),
  });
});
