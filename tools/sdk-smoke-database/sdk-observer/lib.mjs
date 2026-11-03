// Small helpers of the RTDB SDK small observer: counter, journal, admin REST, approval line, claim files, ADC. No SDK, no browser.
import { createHash } from 'node:crypto';
import { constants, openSync, writeSync, fsyncSync, closeSync, readFileSync, readdirSync, unlinkSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const clip = (text, max = 65536) => (text.length > max ? `${text.slice(0, max)}...[clipped ${text.length - max}]` : text);
export class CapExceeded extends Error {}
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
export function createJournal(file, { maxBytes = 16 << 20, softBytes = 12 << 20 } = {}) {
  const fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_APPEND | constants.O_NOFOLLOW, 0o600), secrets = new Set(); let bytes = 0;
  return {
    addSecret: s => { if (typeof s === 'string' && s.length >= 8) secrets.add(s); },
    write(row, { optional = false } = {}) {
      const text = `${JSON.stringify({ t: new Date().toISOString(), ...row })}\n`, size = Buffer.byteLength(text);
      if (optional && bytes + size > softBytes) return false;
      if (bytes + size > maxBytes) throw new Error('Journal cap');
      for (const s of secrets) if (text.includes(s)) throw new Error('Secret in journal row');
      writeSync(fd, text); bytes += size; return true;
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
  };
}

// Admin REST with a fixed timeout on every request. An unknown outcome (timeout, network error) is journalled and thrown, never retried here.
export function createAdmin({ headers, journal, counter, fetchImpl = fetch, timeoutMs = 10000 }) {
  const unknownMutations = [];   // survives promise settlement: the server may still apply such a request later
  return {
    unknownMutations,
    async rest(label, method, url, { body, cleanup = false } = {}) {
      counter.take(label, cleanup ? 'reserve' : 'direct');
      const note = row => { try { journal.write(row); } catch (error) { if (!cleanup && row.kind === 'admin-req') throw error; } };   // a cleanup request never depends on the journal; nothing else is sent when the journal is down
      note({ kind: 'admin-req', label, method, url, body: body === undefined ? null : clip(body) });
      let res, text;
      try {
        res = await fetchImpl(url, { method, redirect: 'manual', headers: { ...headers, ...(body === undefined ? {} : { 'content-type': 'application/json' }) }, body, signal: AbortSignal.timeout(timeoutMs) });
        text = clip(await res.text());
      } catch (error) { note({ kind: 'admin-unknown', label, error: String(error?.name) }); if (method !== 'GET') unknownMutations.push(label); throw new Unknown(`${label}: unknown outcome`); }
      note({ kind: 'admin-res', label, status: res.status, body: text });
      return { status: res.status, text };
    },
  };
}

// `- <date> | RTDB-SMALL-OBSERVER <runId> | decision=APPROVE; scriptSha256=..; directCap=..; adc=1; prefix=..; basis=2196 | coordinator | <source>`: exactly one such line, every field equal.
export function checkApproval(ledgerText, want) {
  const lines = ledgerText.split('\n').filter(l => l.includes(`| RTDB-SMALL-OBSERVER ${want.runId} |`));
  if (lines.length !== 1) throw new Error(`approval lines for ${want.runId}: ${lines.length}`);
  const parts = lines[0].split(' | ');
  if (parts.length !== 5 || parts[1] !== `RTDB-SMALL-OBSERVER ${want.runId}` || parts[3] !== 'coordinator') throw new Error('approval line shape');
  const fields = Object.fromEntries(parts[2].split('; ').map(f => { const i = f.indexOf('='); return [f.slice(0, i), f.slice(i + 1)]; }));
  const expected = { decision: 'APPROVE', scriptSha256: want.scriptSha256, directCap: String(want.directCap), adc: '1', prefix: want.prefix, basis: '2196' };
  if (Object.keys(fields).sort().join() !== Object.keys(expected).sort().join() || Object.entries(expected).some(([k, v]) => fields[k] !== v)) throw new Error('approval fields differ');
}

// Claim files (project lease, RECORDING): O_EXCL, 0600; released only if still ours.
export function claim(file, content) {
  const fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeSync(fd, content); fsyncSync(fd); } finally { closeSync(fd); }
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
