// node --test require-browser.test.mjs: the policy for a missing browser. A test that needs Chromium skips
// when it cannot run (a developer machine without the browser), and fails when FIREEMU_REQUIRE_BROWSER=1
// (CI installs the browser, so a skip there would hide the whole file).
import test from 'node:test';
import assert from 'node:assert/strict';
import { browserRequired, missingPlaywright, launchOrSkip } from './require-browser.mjs';

const skipper = () => { const calls = []; const t = { skip: (why) => calls.push(why) }; return { t, calls }; };
const browser = { close: async () => {} };

test('only FIREEMU_REQUIRE_BROWSER=1 requires the browser, nothing else that looks true', () => {
  assert.equal(browserRequired({ FIREEMU_REQUIRE_BROWSER: '1' }), true);
  for (const value of [undefined, '', '0', 'true', 'yes', ' 1', '1 ', 'false']) assert.equal(browserRequired({ FIREEMU_REQUIRE_BROWSER: value }), false, String(value));
  assert.equal(browserRequired({}), false);
});

test('a browser that launches is returned and nothing is skipped', async () => {
  const { t, calls } = skipper();
  for (const env of [{}, { FIREEMU_REQUIRE_BROWSER: '1' }]) {
    const chromium = { launch: async (options) => { assert.deepEqual(options, { headless: true }); return browser; } };
    assert.equal(await launchOrSkip(chromium, t, env), browser);
  }
  assert.deepEqual(calls, []);
});

test('a browser that cannot launch skips the test with the reason, unless the browser is required', async () => {
  const { t, calls } = skipper();
  const chromium = { launch: async () => { throw new Error('no chrome here'); } };
  assert.equal(await launchOrSkip(chromium, t, {}), null);
  assert.deepEqual(calls, ['Chromium cannot be launched']);
  await assert.rejects(launchOrSkip(chromium, t, { FIREEMU_REQUIRE_BROWSER: '1' }), /FIREEMU_REQUIRE_BROWSER=1.*no chrome here/s);
  assert.equal(calls.length, 1, 'the required run does not skip');
});

test('Playwright missing: a skip reason without the requirement, an error with it', () => {
  assert.equal(missingPlaywright(undefined, {}), 'playwright is not installed');
  assert.equal(missingPlaywright({ launch() {} }, {}), false);
  assert.throws(() => missingPlaywright(undefined, { FIREEMU_REQUIRE_BROWSER: '1' }), /FIREEMU_REQUIRE_BROWSER=1.*playwright is not installed/s);
  assert.equal(missingPlaywright({ launch() {} }, { FIREEMU_REQUIRE_BROWSER: '1' }), false);
});
