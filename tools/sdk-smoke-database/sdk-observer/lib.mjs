// Small helpers of the RTDB SDK small observer: counter, journal, admin REST, approval line, claim files, ADC. No SDK, no browser.
import { createHash } from 'node:crypto';
import { constants, openSync, writeSync, fsyncSync, closeSync, readFileSync, readdirSync, unlinkSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

/** Writes all of `data` through `write` (fs.writeSync by default), looping over short writes; a write that makes no progress is an error. */
export function writeAll(fd, data, write = writeSync) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
  for (let off = 0; off < buf.length;) { const n = write(fd, buf, off, buf.length - off); if (!(n > 0)) throw new Error('short write made no progress'); off += n; }
}
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const clip = (text, max = 65536) => (text.length > max ? `${text.slice(0, max)}...[clipped ${text.length - max}]` : text);
export class CapExceeded extends Error {}
/** A complete answer that does not settle a mutation: below 200, 3xx or 5xx. */
export const unknownStatus = status => status < 200 || (status >= 300 && status < 400) || status >= 500;
export class Unknown extends Error {}

// The approval line binds this exact code: sha256 over "<sha256>  <name>" lines of the top-level *.mjs, *.html and package.json.
export function scriptManifest(dir) {
  const files = readdirSync(dir).filter(n => /\.(mjs|html)$|^package\.json$/.test(n)).sort();
  return { files, sha256: sha256(files.map(n => `${sha256(readFileSync(path.join(dir, n)))}  ${n}\n`).join('')) };
}

// One bounded counter: `direct` for every request that leaves the machine (admin, tokeninfo, WS connect, LP request), a separate reserve for cleanup so the cap can never block the restore.
export function createCounter({ direct, reserve = 12 }) {
  const used = { direct: 0, reserve: 0, adc: 0 }, caps = { direct, reserve, adc: 1 };
  return {
    take(label, kind = 'direct') { if (used[kind] >= caps[kind]) throw new CapExceeded(`${kind} cap ${caps[kind]} reached at ${label}`); used[kind]++; },
    overflow() { used.overflow = (used.overflow ?? 0) + 1; },   // a request seen after the cap was reached: counted, not hidden
    used: () => ({ ...used }), caps: () => ({ ...caps }),
  };
}

// Append-only JSONL, created O_EXCL, 0600. A row that contains a secret is refused. `optional` rows (raw capture) are dropped once the file passes the soft cap.
export function createJournal(file, { maxBytes = 16 << 20, softBytes = 12 << 20, write: rawWrite = writeSync } = {}) {
  const fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_APPEND | constants.O_NOFOLLOW, 0o600), secrets = new Set(); let bytes = 0;
  return {
    addSecret: s => { if (typeof s === 'string' && s.length >= 8) secrets.add(s); },
    write(row, { optional = false } = {}) {
      const text = `${JSON.stringify({ t: new Date().toISOString(), ...row })}\n`, size = Buffer.byteLength(text);
      if (optional && bytes + size > softBytes) return false;
      if (bytes + size > maxBytes) throw new Error('Journal cap');
      for (const s of secrets) if (text.includes(s)) throw new Error('Secret in journal row');
      writeAll(fd, text, rawWrite); bytes += size; return true;
    },
    close() { try { fsyncSync(fd); } finally { closeSync(fd); } },
  };
}

export function targetUrls(t) {
  const production = t.kind === 'production';
  return {
    data: p => (production ? `https://${t.namespace}.firebaseio.com/${p}.json` : `http://${t.host}/${p}.json?ns=${t.namespace}`),
    databaseURL: production ? `https://${t.namespace}.firebaseio.com` : `http://${t.host}?ns=${t.namespace}`,
    instance: production ? `https://firebasedatabase.googleapis.com/v1beta/projects/${t.projectNumber}/locations/${t.region}/instances/${t.namespace}` : null,
    // the rest suite: a path (with its .json) and a query string as the case wrote them; locally the namespace parameter goes first
    raw: (p, query) => (production ? `https://${t.namespace}.firebaseio.com/${p}${query ? `?${query}` : ''}` : `http://${t.host}/${p}?ns=${t.namespace}${query ? `&${query}` : ''}`),
  };
}

// The request headers a caller may add (the rest suite) and the response headers it records. Nothing else is journalled:
// the Authorization header and the token never are.
export const EXTRA_REQUEST_HEADERS = ['if-none-match', 'x-http-method-override', 'x-firebase-etag', 'accept-encoding', 'if-match'];
export const RECORDED_RESPONSE_HEADERS = ['etag', 'content-type', 'content-length', 'content-disposition', 'cache-control', 'location', 'allow', 'www-authenticate', 'access-control-allow-origin', 'access-control-expose-headers', 'vary'];
const BODY_MAX = 65536;

// Admin REST with a fixed timeout on every request. An unknown outcome (timeout, network error) is journalled and thrown, never retried here.
// `record` (the rest suite only): the extra request headers are sent and journalled, the answer keeps its byte length,
// UTF-8 validity and the allowlisted response headers, on the admin-res row and in the return value.
// `anonymous` (the rules suite's case requests only, with `record`): the request carries none of the credential headers
// (no Authorization, no x-goog-user-project), as an unauthenticated client sends it; the admin-req row says so.
// `bearer` (the tokens suite only, with `anonymous`): the request carries `Authorization: Bearer <bearer>` and nothing
// else of the credential; the admin-req row keeps only the token's sha256. `resolveAdc` (the tokens suite only, with
// `anonymous`): the URL carries the placeholder {adc} exactly once, replaced by the ADC token (`adc`) in the URL that is
// fetched only; the journal keeps the placeholder, and the token is masked as {adc} in the answer's text and headers.
export const ADC_PLACEHOLDER = '{adc}';
export function createAdmin({ headers, journal, counter, fetchImpl = fetch, timeoutMs = 10000, adc }) {
  const unknownMutations = [];   // survives promise settlement: the server may still apply such a request later
  return {
    unknownMutations,
    async rest(label, method, url, { body, cleanup = false, headers: extra, record = false, anonymous = false, bearer, resolveAdc = false } = {}) {
      if (extra !== undefined && !record) throw new Error('extra request headers need record');
      if (anonymous && (!record || cleanup)) throw new Error('anonymous needs record');
      if ((bearer !== undefined || resolveAdc) && !(record && anonymous)) throw new Error('a token credential needs record and anonymous');
      if (bearer !== undefined && (typeof bearer !== 'string' || bearer.length > 8192 || !/^[\x20-\x7e]*$/.test(bearer))) throw new Error('bearer token shape');
      if (String(url).split(ADC_PLACEHOLDER).length !== (resolveAdc ? 2 : 1)) throw new Error('resolveAdc needs exactly one {adc} placeholder, and only resolveAdc may carry one');
      if (resolveAdc && (typeof adc !== 'string' || adc.length === 0)) throw new Error('resolveAdc: no ADC value');
      for (const name of Object.keys(extra ?? {})) if (!EXTRA_REQUEST_HEADERS.includes(name) || typeof extra[name] !== 'string') throw new Error(`request header ${name} is not recorded`);   // before the counter: nothing is sent
      counter.take(label, cleanup ? 'reserve' : 'direct');
      const note = row => { try { journal.write(row); } catch (error) { if (!cleanup && row.kind === 'admin-req') throw error; } };   // a cleanup request never depends on the journal; nothing else is sent when the journal is down
      note({ kind: 'admin-req', label, method, url, body: body === undefined ? null : clip(body), ...(record ? { headers: { ...(extra ?? {}) } } : {}), ...(anonymous ? { anonymous: true } : {}), ...(bearer !== undefined ? { bearerSha256: sha256(bearer) } : {}), ...(resolveAdc ? { resolveAdc: true } : {}) });
      const hide = resolveAdc ? t => (typeof t === 'string' ? t.split(adc).join(ADC_PLACEHOLDER).split(encodeURIComponent(adc)).join(ADC_PLACEHOLDER) : t) : t => t;
      let res, text, bytes;
      try {
        res = await fetchImpl(resolveAdc ? url.replace(ADC_PLACEHOLDER, encodeURIComponent(adc)) : url, { method, redirect: 'manual', headers: { ...(anonymous ? {} : headers), ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...(extra ?? {}), ...(bearer !== undefined ? { authorization: `Bearer ${bearer}` } : {}) }, body, signal: AbortSignal.timeout(timeoutMs) });
        if (record) bytes = Buffer.from(await res.arrayBuffer()); else text = clip(await res.text());
      } catch (error) { note({ kind: 'admin-unknown', label, error: String(error?.name) }); if (method !== 'GET') unknownMutations.push(label); throw new Unknown(`${label}: unknown outcome`); }
      if (!record) { note({ kind: 'admin-res', label, status: res.status, body: text }); return { status: res.status, text }; }
      let decoded = null;
      try { decoded = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } catch { /* not UTF-8: recorded as such */ }
      if (decoded === null && method !== 'GET') unknownMutations.push(label);   // an answer to a mutation that cannot be read is no answer: the outcome is unknown (Codex review of packet 2)
      const clipped = decoded !== null && decoded.length > BODY_MAX, answer = {
        status: res.status, text: decoded === null ? null : hide(decoded.slice(0, BODY_MAX)),
        headers: Object.fromEntries(RECORDED_RESPONSE_HEADERS.flatMap(name => (res.headers.get(name) === null ? [] : [[name, hide(res.headers.get(name))]]))),
        bodyBytes: bytes.length, utf8: decoded !== null, clipped,
      };
      note({ kind: 'admin-res', label, status: answer.status, body: answer.text, headers: answer.headers, bodyBytes: answer.bodyBytes, utf8: answer.utf8, clipped });
      return answer;
    },
  };
}

// `- <date> | RTDB-SMALL-OBSERVER <runId> | decision=APPROVE; scriptSha256=..; directCap=..; adc=1; prefix=..; basis=2196 | coordinator | <source>`: exactly one such line, every field equal.
// The events, admin, rest, rules and tokens suites (packets 1 to 3 and 5 of the RTDB closure, owner row 2217) add `suite=<events|admin|events+admin|rest|rules|tokens>` and carry basis=2217.
export function checkApproval(ledgerText, want) {
  if (ledgerText.split('\n').some(l => /^REVOKED\b/.test(l.split(' | ')[1] ?? '') && l.includes(want.runId))) throw new Error(`approval revoked: a REVOKED line names ${want.runId}`);   // a consumed or withdrawn line never approves again
  const lines = ledgerText.split('\n').filter(l => l.includes(`| RTDB-SMALL-OBSERVER ${want.runId} |`));
  if (lines.length !== 1) throw new Error(`approval lines for ${want.runId}: ${lines.length}`);
  const parts = lines[0].split(' | ');
  if (parts.length !== 5 || parts[1] !== `RTDB-SMALL-OBSERVER ${want.runId}` || parts[3] !== 'coordinator') throw new Error('approval line shape');
  const pairs = parts[2].split('; ').map(f => { const i = f.indexOf('='); return [f.slice(0, i), f.slice(i + 1)]; });
  if (new Set(pairs.map(([k]) => k)).size !== pairs.length) throw new Error('approval fields repeated');   // a repeated field would be silently collapsed: "decision=REVOKED; decision=APPROVE" must not pass
  const fields = Object.fromEntries(pairs);
  const suite = want.suite ?? 'small';
  if (!['small', 'events', 'admin', 'events+admin', 'rest', 'rules', 'tokens'].includes(suite)) throw new Error('approval suite');
  const expected = { decision: 'APPROVE', scriptSha256: want.scriptSha256, directCap: String(want.directCap), adc: '1', prefix: want.prefix, ...(suite === 'small' ? { basis: '2196' } : { suite, basis: '2217' }) };
  if (Object.keys(fields).sort().join() !== Object.keys(expected).sort().join() || Object.entries(expected).some(([k, v]) => fields[k] !== v)) throw new Error('approval fields differ');
}

// Claim files (project lease, RECORDING): O_EXCL, 0600; released only if still ours.
export function claim(file, content, write = writeSync) {
  const fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeAll(fd, content, write); fsyncSync(fd); } finally { closeSync(fd); }
  return () => { if (readFileSync(file, 'utf8') === content) unlinkSync(file); };
}

// ADC: the gcloud access token (scrubbed environment) and one tokeninfo check of scopes and principal.
export const mintToken = gcloud => execFileSync(gcloud, ['auth', 'application-default', 'print-access-token'], { stdio: ['ignore', 'pipe', 'ignore'], timeout: 60000, env: { PATH: '/usr/bin:/bin', HOME: process.env.HOME } }).toString().trim();
export async function adcVerdict(fetchImpl, token, principalSha256) {
  try {
    const res = await fetchImpl('https://oauth2.googleapis.com/tokeninfo', { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ access_token: token }).toString(), signal: AbortSignal.timeout(25000) });
    const doc = res.status >= 200 && res.status < 300 ? JSON.parse(await res.text()) : null, scopes = (doc?.scope ?? '').split(/\s+/);
    if (!doc || !scopes.includes('https://www.googleapis.com/auth/userinfo.email') || !(scopes.includes('https://www.googleapis.com/auth/cloud-platform') || scopes.includes('https://www.googleapis.com/auth/firebase.database')) || typeof doc.email !== 'string') return { ok: false, reason: 'adc-scopes' };
    return sha256(doc.email) === principalSha256 ? { ok: true } : { ok: false, reason: 'adc-principal' };
  } catch { return { ok: false, reason: 'adc-unverified' }; }
}
