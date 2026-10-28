// Scoped REST support for the fresh stage-context database. The caller owns the durable journal.
import { isDeepStrictEqual } from 'node:util';
import { buildRestRequest, documentsName, guardRestRequest } from './harness.mjs';
import { stageContextSeed } from './stage-context-corpus.mjs';

const MAX_BODY = 1024 * 1024;
async function readBounded(response) {
  if (!response.body) {
    const bytes = Buffer.from(await response.text());
    if (bytes.length > MAX_BODY) throw new Error('response body limit');
    return bytes;
  }
  const parts = []; let length = 0;
  for await (const chunk of response.body) {
    length += chunk.length;
    if (length > MAX_BODY) throw new Error('response body limit');
    parts.push(Buffer.from(chunk));
  }
  return Buffer.concat(parts);
}

export function createStageSupport(ctx, { fetchFn = fetch, journal, claim, timeoutMs = 60000 } = {}) {
  if (ctx.stageContextDatabase !== ctx.database || typeof journal !== 'function' || typeof claim !== 'function') throw new Error('unbound stage support');
  const documents = stageContextSeed();
  const paths = documents.map(([path]) => path);
  let phase = 'initial';
  async function request(op, step) {
    const built = buildRestRequest({id:op, ...step}, ctx, new Map());
    guardRestRequest(built, ctx, {harness:true});
    await claim(op);
    await journal({phase:'attempt', op, method:built.init.method, url:built.url, body:built.init.body ?? null});
    let response, bytes;
    try {
      response = await fetchFn(built.url, {...built.init, redirect:'error', signal:AbortSignal.timeout(timeoutMs)});
      await journal({phase:'headers', op, status:response.status});
      bytes = await readBounded(response);
    } catch {
      await journal({phase:'unknown', op});
      throw new Error(`unknown ${op}; retain claims`);
    }
    await journal({phase:'response', op, status:response.status, bodyBase64:bytes.toString('base64')});
    if (response.status !== 200) throw new Error(`known rejection ${op}; retain claims`);
    try { return JSON.parse(bytes.toString('utf8')); } catch { throw new Error(`invalid ${op} response; retain claims`); }
  }
  async function stageOperation(op, detail = {}) {
    const expectedPhase = {baseline:'initial', seed:'baseline', verify:'seeded', 'delete-owned':'verified', 'verify-absence':'deleted'}[op];
    if (!expectedPhase || phase !== expectedPhase) throw new Error('invalid support sequence');
    try {
    if (op === 'seed') {
      if (!isDeepStrictEqual(detail.documents, documents)) throw new Error('unexpected seed');
      await request(op, {rpc:'commit', body:{writes:documents.map(([path, fields]) => ({update:{name:`${documentsName(ctx)}/${path}`,fields}}))}});
    } else if (op === 'delete-owned') {
      if (!isDeepStrictEqual(detail.paths, paths)) throw new Error('unexpected cleanup paths');
      await request(op, {rpc:'commit', body:{writes:paths.map(path => ({delete:`${documentsName(ctx)}/${path}`}))}});
    } else if (['baseline','verify','verify-absence'].includes(op)) {
      if (op === 'verify' && !isDeepStrictEqual(detail.documents, documents)) throw new Error('unexpected verification seed');
      if (op === 'verify-absence' && !isDeepStrictEqual(detail.paths, paths)) throw new Error('unexpected absence paths');
      const rows = await request(op, {rpc:'runQuery',body:{structuredQuery:{from:[{allDescendants:true}],select:{fields:[{fieldPath:'__name__'}]},orderBy:[{field:{fieldPath:'__name__'},direction:'ASCENDING'}],limit:paths.length+1}}});
      if (!Array.isArray(rows) || rows.some(row => !row || typeof row !== 'object' || Array.isArray(row) || Object.keys(row).some(key => !['document','readTime'].includes(key)) || (row.document !== undefined && (!row.document || typeof row.document.name !== 'string')) || (row.document === undefined && typeof row.readTime !== 'string'))) throw new Error('invalid scoped read');
      const names = rows.filter(row => row.document).map(row => row.document.name).sort();
      const expected = op === 'verify' ? paths.map(path => `${documentsName(ctx)}/${path}`).sort() : [];
      if (!isDeepStrictEqual(names, expected)) throw new Error('scoped read mismatch');
    } else throw new Error('unsupported stage-context support action');
    phase = {baseline:'baseline', seed:'seeded', verify:'verified', 'delete-owned':'deleted', 'verify-absence':'initial'}[op];
    return {known:true,ok:true};
    } catch (error) { phase = 'unknown'; throw error; }
  }
  return {stageOperation, close:async () => {}};
}
