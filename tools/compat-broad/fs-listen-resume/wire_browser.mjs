/** Route every page request through one pre-send browser request budget. */
export const installBrowserWireGuard = async ({ context, budget, phase, allowUrl }) => {
  if (typeof context?.route !== 'function' || typeof budget?.claim !== 'function' ||
      typeof phase !== 'function' || typeof allowUrl !== 'function') {
    throw new Error('invalid browser wire guard inputs');
  }
  let failure = null;
  await context.route('**/*', async route => {
    const url = route.request().url();
    if (!allowUrl(url)) {
      failure ??= 'wire-destination';
      await route.abort();
      return;
    }
    try {
      budget.claim(phase(), 'browser');
    } catch {
      failure ??= 'wire-request-budget';
      await route.abort();
      return;
    }
    try {
      await route.continue();
    } catch {
      failure ??= 'wire-transport';
    }
  });
  return Object.freeze({ failure: () => failure });
};
