/** Create an authenticated control client from explicit endpoints or fireemu exec's environment. */
export function createControlClient(options = {}) {
  const {origin: suppliedOrigin, apiBaseUrl: suppliedBase, env = process.env, requestTimeoutMs = 10_000} = options;
  if (suppliedOrigin !== undefined && suppliedBase !== undefined) {
    throw new TypeError('Specify origin or apiBaseUrl, not both');
  }
  const explicit = suppliedOrigin !== undefined || suppliedBase !== undefined;
  const endpoint = suppliedOrigin ?? suppliedBase ?? env.FIREEMU_CONTROL_URL;
  const token = options.token ?? (explicit ? undefined : env.FIREEMU_CONTROL_TOKEN);
  if (typeof endpoint !== 'string' || endpoint.length === 0) {
    throw new TypeError('Specify origin or apiBaseUrl, or set FIREEMU_CONTROL_URL');
  }
  let parsed;
  try { parsed = new URL(endpoint); }
  catch { throw new TypeError('Control endpoint must be an absolute HTTP(S) URL'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.href.includes('?') || parsed.href.includes('#')) {
    throw new TypeError('Control endpoint must be HTTP(S), without credentials, query or fragment');
  }
  const paths = suppliedOrigin !== undefined ? ['/'] : suppliedBase !== undefined ? ['/v1', '/v1/'] : ['/', '/v1', '/v1/'];
  if (!paths.includes(parsed.pathname)) throw new TypeError('Control origin must have no path; apiBaseUrl must end in /v1/');
  if (typeof token !== 'string' || !/^[\x21-\x7e]+$/.test(token)) {
    throw new TypeError('Specify a nonempty ASCII control token without whitespace, or set FIREEMU_CONTROL_TOKEN');
  }
  if (!Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs <= 0 || requestTimeoutMs > 2_147_483_647) {
    throw new TypeError('requestTimeoutMs must be a positive integer at most 2147483647');
  }
  const origin = parsed.origin;
  const apiBaseUrl = `${origin}/v1/`;
  return Object.freeze({
    origin,
    apiBaseUrl,
    async request(method, path, body, {signal} = {}) {
      // Paths are relative to this capability's endpoint; neither URLs nor redirects may change it.
      if (typeof path !== 'string' || !path || /[\x00-\x20\x7f\\#]/.test(path) || path.startsWith('//') || /^[a-z][a-z0-9+.-]*:/i.test(path)) {
        throw new TypeError('Control path must be API-relative or root-relative, not a URL');
      }
      const url = new URL(path, apiBaseUrl);
      if (url.origin !== origin) throw new TypeError('Control path must stay on the configured origin');
      const response = await fetch(url, {
        method,
        headers: {authorization:`Bearer ${token}`, ...(body === undefined ? {} : {'content-type':'application/json'})},
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: 'error',
        signal: signal ?? AbortSignal.timeout(requestTimeoutMs),
      });
      const text = await response.text();
      let value;
      try { value = text === '' ? undefined : JSON.parse(text); }
      catch {
        if (response.ok) throw controlError(response.status, 'invalid JSON response');
      }
      if (!response.ok) throw controlError(response.status, value?.error?.message ?? (value === undefined ? response.statusText : JSON.stringify(value)));
      return value;
    },
  });
}

function controlError(status, message) {
  return Object.assign(new Error(`control ${status}: ${message}`), {code:'FIREEMU_CONTROL_HTTP', status});
}
