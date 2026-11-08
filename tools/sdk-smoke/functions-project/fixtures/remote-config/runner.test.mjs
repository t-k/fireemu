import assert from 'node:assert/strict';
import test from 'node:test';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {dirname, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const source = dirname(fileURLToPath(import.meta.url));
const runner = resolve(source, '../../../../runner-node/index.mjs');
const encode = value => { const bytes = Buffer.from(JSON.stringify(value)); return Buffer.concat([Buffer.from(bytes.length + '\n'), bytes]); };

for (const profile of ['strict', 'emulator']) {
  test(`real SDK Remote Config discovery and delivery (${profile})`, {timeout: 15000}, async t => {
    const child = spawn(process.execPath, [runner, '--source', source], {
      env: {...process.env, GCLOUD_PROJECT: 'demo-remote-config', FIREEMU_HTTP_PROFILE: profile, REMOTE_CONFIG_NEAR_MISS: '1'},
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const exited = once(child, 'exit');
    let done = false, buffer = Buffer.alloc(0), stderr = '';
    exited.then(() => { done = true; });
    child.stdin.on('error', () => {});
    const frames = [];
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.stdout.on('data', chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      for (;;) {
        const at = buffer.indexOf(10); if (at < 0) return;
        const n = Number(buffer.subarray(0, at)); if (buffer.length < at + 1 + n) return;
        frames.push(JSON.parse(buffer.subarray(at + 1, at + 1 + n)));
        buffer = buffer.subarray(at + 1 + n);
      }
    });
    t.after(async () => {
      if (!done) child.kill('SIGTERM');
      await exited;
      child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy();
    });
    const wait = async predicate => {
      for (let n = 0; n < 1000; n++) {
        const value = frames.find(predicate); if (value) return value;
        assert.equal(done, false, stderr);
        await new Promise(r => setTimeout(r, 5));
      }
      throw new Error('runner frame timeout: ' + stderr);
    };
    const hello = await wait(f => f.type === 'hello');
    assert.deepEqual(hello.manifest.functions.map(f => [f.name, f.trigger.type]), [
      ['configV1', 'remoteConfig'], ['configV2', 'remoteConfig'],
    ]);
    assert.equal(hello.manifest.ignored.length, 1);
    assert.equal(hello.manifest.ignored[0].name, 'nearMiss');
    for (const generation of [1, 2]) {
      const data = {versionNumber: 7, updateTime: '2026-01-02T03:04:05Z'};
      const context = generation === 1
        ? {eventId: 'first-id', timestamp: '2026-01-02T03:04:06Z', eventType: 'google.firebase.remoteconfig.update', resource: {service: 'firebaseremoteconfig.googleapis.com', name: 'projects/demo-remote-config'}}
        : {specversion: '1.0', id: 'second-id', time: '2026-01-02T03:04:07Z', type: 'google.firebase.remoteconfig.remoteConfig.v1.updated', source: '//firebaseremoteconfig.googleapis.com/projects/demo-remote-config'};
      const event = generation === 1 ? {data, context} : {...context, data};
      child.stdin.write(encode({type: 'invoke', invocationId: `remote-${generation}`, function: `configV${generation}`, entryPoint: `configV${generation}`, trigger: 'remoteConfig', event}));
      const result = await wait(f => f.type === 'result' && f.invocationId === `remote-${generation}`);
      assert.equal(result.ok, true, JSON.stringify(result));
      const log = await wait(f => f.type === 'log' && f.invocationId === `remote-${generation}` && f.message.startsWith('REMOTE_CONFIG_EVENT '));
      const observed = JSON.parse(log.message.slice('REMOTE_CONFIG_EVENT '.length));
      assert.deepEqual(observed.data, data);
      for (const [key, value] of Object.entries(context)) assert.deepEqual(observed.context[key], value);
      assert.equal(Object.hasOwn(observed.context, 'traceparent'), false);
      assert.equal(Object.hasOwn(observed.data, 'updateUser'), false);
      assert.equal(Object.hasOwn(observed.data, 'rollbackSource'), false);
    }
  });
}
