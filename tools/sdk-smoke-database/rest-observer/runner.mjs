import { isDeepStrictEqual } from 'node:util';
import { checkAnchor } from './packet-gate.mjs';

// Transport-independent corpus kernel; not a live sender or authorization gate.
export async function execute(state, transport, request) {
  if (state.unknown) throw Error('sticky unknown');
  if (state.used >= state.max || (request.phase !== 'cleanup' && state.used >= state.max - state.cleanupReserve)) throw Error('request budget');
  state.used++;
  state.journal.push({ state: 'before-send', request });
  let response;
  try { response = await transport(request); } catch { state.unknown = true; throw Error('unknown response'); }
  if (!response || !Number.isInteger(response.status) || response.status < 200 || response.status >= 300 || typeof response.body !== 'string' || !response.headers || typeof response.headers !== 'object') {
    state.unknown = true;
    throw Error('unknown response');
  }
  state.journal.push({ state: 'response-persisted', response });
  return response;
}

export async function runCorpus(state, transport, prefix, anchors) {
  if (!/^[a-zA-Z0-9_-]+$/.test(prefix)) throw Error('invalid prefix');
  const call = (method, path, body, query, phase = 'normal') => execute(state, transport, { method, path: `/${prefix}/${path}.json`, body, query, phase });
  for (const round of ['r1', 'r2']) {
    const seed = [ ['tree', '{"scalar":1,"child":{"x":2}}'], ['patch', '{"x":1,"y":{"z":"s"}}'], ['query', '{"a":{"h":3},"b":{"h":1},"c":{"h":2},"d":{},"10":{"h":5},"2":{"h":5}}'] ];
    for (const [name, body] of seed) await call('PUT', `${round}/${name}`, body);
    for (const [name, body] of seed) {
      const read = await call('GET', `${round}/${name}`);
      let value; try { value = JSON.parse(read.body); } catch { throw Error('seed mismatch'); }
      const expected = JSON.parse(body); if (name === 'query') delete expected.d;
      if (!isDeepStrictEqual(value, expected)) throw Error('seed mismatch');
    }
    const post = await call('POST', `${round}/push`, '{"v":1}');
    let key;
    try { key = JSON.parse(post.body).name; } catch { throw Error('invalid POST response'); }
    if (typeof key !== 'string' || !/^[-A-Za-z0-9_]{1,128}$/.test(key)) throw Error('invalid generated key');
    const child = await call('GET', `${round}/push/${key}`);
    let childValue; try { childValue = JSON.parse(child.body); } catch { throw Error('child mismatch'); }
    if (!isDeepStrictEqual(childValue, { v: 1 })) throw Error('child mismatch');
    await call('DELETE', `${round}/push/${key}`);
    const absent = await call('GET', `${round}/push/${key}`);
    if (absent.body.trim() !== 'null') throw Error('child absence mismatch');
    await call('GET', `${round}/tree`, undefined, 'shallow=true');
    await call('PUT', `${round}/silent`, '{"a":1}', 'print=silent');
    await call('PATCH', `${round}/silent`, '{"b":2}', 'print=silent');
    await call('PUT', `${round}/limited`, '{"v":1}', 'writeSizeLimit=small');
    const patchAnchor = await call('PATCH', `${round}/patch`, '{"y/z":"t","w":3}');
    const queryRequest = { method:'GET', path:`/${prefix}/${round}/query.json`, body:undefined, query:'orderBy=%22h%22&startAt=2', phase:'normal' };
    const queryAnchor = await execute(state, transport, queryRequest);
    if (anchors) { checkAnchor(patchAnchor, anchors[round].patch); checkAnchor(queryAnchor, anchors[round].query, queryRequest); }
    await call('DELETE', round, undefined, undefined, 'cleanup');
    const cleaned = await call('GET', round, undefined, undefined, 'cleanup');
    if (cleaned.body.trim() !== 'null') throw Error('round cleanup not verified');
  }
}
