import { isDeepStrictEqual } from 'node:util';
const PREFIX = /^rnext1_[a-f0-9]{24}$/;
const stamp = { '.sv': 'timestamp' };
const inc = { '.sv': { increment: 5 } };

export function serverValueCases() {
  return [
    { id: 'timestamp-single', seed: null, method: 'PUT', body: stamp },
    { id: 'increment-numeric', seed: 7, method: 'PUT', body: inc },
    { id: 'increment-absent', seed: null, method: 'PUT', body: inc },
    { id: 'increment-nonnumeric', seed: 'old', method: 'PUT', body: inc },
    { id: 'multipath-one-clock', seed: { counter: 7 }, method: 'PATCH', body: { first: stamp, second: stamp, counter: inc } },
  ];
}

export function serverValueRules(prefix) {
  if (!PREFIX.test(prefix)) throw Error('invalid prefix');
  return { rules: { '.read': false, '.write': false, [prefix]: { '.read': true, '.write': true, ready: { '.read': true } } } };
}

function responseValue(response) {
  if (response?.status !== 200 || typeof response.body !== 'string') throw Error('server value response unresolved');
  try { return JSON.parse(response.body); } catch { throw Error('server value response unreadable'); }
}

export async function runServerValueCorpus(transport, prefix, now = Date.now) {
  if (!PREFIX.test(prefix) || typeof transport !== 'function' || typeof now !== 'function') throw Error('invalid server value corpus');
  const rows = [];
  for (const round of ['r1', 'r2']) for (const item of serverValueCases()) {
    const path = `/${prefix}/${round}/${item.id}.json`;
    const request = (step, method, body) => ({ step, method, path, ...(body === undefined ? {} : { body: JSON.stringify(body) }), phase: 'normal' });
    responseValue(await transport(request('sv-seed', 'PUT', item.seed)));
    const before = await transport(request('sv-before', 'GET'));
    const preimage = responseValue(before);
    if (!isDeepStrictEqual(preimage, item.seed)) throw Error('server value preimage unresolved');
    const writeRequest = request('sv-write', item.method, item.body);
    const startedAt = now();
    const writeResponse = await transport(writeRequest);
    const endedAt = now();
    const value = responseValue(writeResponse);
    const after = await transport(request('sv-after', 'GET'));
    const readback = responseValue(after);
    const response = r => ({ status: r.status, body: r.body, etag: r.headers?.etag ?? null });
    rows.push({ id: item.id, round, preimage, before: response(before), request: writeRequest, startedAt, endedAt, response: response(writeResponse), value, readback, after: response(after), ...(item.id === 'multipath-one-clock' ? { sameClock: Number.isSafeInteger(readback?.first) && Number.isSafeInteger(readback?.second) && readback.first === readback.second } : {}) });
  }
  return rows;
}
