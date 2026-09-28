import { boundLogMessage } from './log-context.mjs';

// User callbacks may reject with anything, including throwing getters or a
// revoked Proxy. Error formatting must not reject a second time and strand the
// daemon's invocation waiter. Do not invoke arbitrary toString/toJSON hooks.
export function invocationFailure(error) {
  let message = 'Function invocation failed';
  if (typeof error === 'string') {
    message = error;
  } else {
    try {
      const candidate = error?.message;
      if (typeof candidate === 'string') message = candidate;
    } catch {
      // Fixed fallback. The accessor's thrown value is not itself formatted.
    }
  }
  let diagnostic = message;
  try {
    const stack = error?.stack;
    if (typeof stack === 'string') diagnostic = stack;
  } catch {
    // Preserve the usable message when only stack access fails.
  }
  return {
    message: boundLogMessage(message, 4096),
    diagnostic: boundLogMessage(diagnostic),
  };
}
