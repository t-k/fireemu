// The policy for a test that needs headless Chromium: it skips on a machine without the browser, and fails
// when FIREEMU_REQUIRE_BROWSER=1 (CI installs the browser first; a skip there would hide the whole file).

/** True only for the exact value `1`. */
export const browserRequired = (env = process.env) => env.FIREEMU_REQUIRE_BROWSER === '1';

/** The `skip` option of a test file: a reason when Playwright is not installed, `false` when it is. Throws instead when the browser is required. */
export function missingPlaywright(chromium, env = process.env) {
  if (chromium) return false;
  if (browserRequired(env)) throw new Error('FIREEMU_REQUIRE_BROWSER=1 but playwright is not installed');
  return 'playwright is not installed';
}

/** Launches headless Chromium. When it cannot start, skips the test (returns null), or throws when the browser is required. */
export async function launchOrSkip(chromium, t, env = process.env) {
  try {
    return await chromium.launch({ headless: true });
  } catch (error) {
    if (browserRequired(env)) throw new Error(`FIREEMU_REQUIRE_BROWSER=1 but Chromium cannot be launched: ${error.message}`);
    t.skip('Chromium cannot be launched');
    return null;
  }
}
