// Preflight of the Application Default Credentials token that a production recorder is about to use, shared by the
// residual recorder (called from its production branch) and usable before any other recorder (the CLI below).
//
//   node adc-preflight.mjs --gcloud <path to gcloud>      # exit 0 ok, 4 stopped; prints the verdict only
//
// Why (2026-10-26, RTDB residual production-1 and production-2): another session re-ran `gcloud auth
// application-default login --scopes=cloud-platform,androidpublisher`. The management APIs accept cloud-platform
// and answered 200; the RTDB instance host authenticates the identity behind a token, needs userinfo.email, and
// answered 401 on the first data request, after the API enable, the undelete and the reenable had been spent.
// One POST to tokeninfo (the token in the form body, never in a URL) before the first sandbox request stops that
// with nothing changed. Only the verdict and the names of missing scopes are returned or written.
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const ADC_ARGS = ['auth', 'application-default', 'print-access-token'];
export const TOKENINFO_URL = 'https://oauth2.googleapis.com/tokeninfo';
export const EMAIL_SCOPE = 'https://www.googleapis.com/auth/userinfo.email';
export const API_SCOPES = ['https://www.googleapis.com/auth/firebase.database', 'https://www.googleapis.com/auth/cloud-platform'];
const TIMEOUT_MS = 25000;

/**
 * The decision, a pure function of the tokeninfo answer. ok needs the email scope, firebase.database or
 * cloud-platform, and a non-empty email. `missing` names what is absent (never the email itself).
 */
export function adcScopeVerdict(doc) {
  if (!doc || typeof doc !== 'object' || typeof doc.scope !== 'string') return { ok: false, reason: 'adc-scopes-unverified', missing: [] };
  const scopes = doc.scope.split(/\s+/).filter(Boolean), missing = [];
  if (!scopes.includes(EMAIL_SCOPE)) missing.push(EMAIL_SCOPE);
  if (!API_SCOPES.some((x) => scopes.includes(x))) missing.push(API_SCOPES.join(' or '));
  if (typeof doc.email !== 'string' || doc.email.trim() === '') missing.push('email');
  return missing.length ? { ok: false, reason: 'adc-scopes-missing', missing } : { ok: true, missing };
}

/** One POST; the answer must be 2xx and readable JSON, anything else is unverified (fail closed). */
export async function adcPreflight(fetchImpl, token) {
  let doc;
  try {
    const res = await fetchImpl(TOKENINFO_URL, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ access_token: token }).toString(), signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (res.status >= 200 && res.status < 300) doc = JSON.parse(await res.text());
  } catch { /* unverified */ }
  return adcScopeVerdict(doc);
}

/** The token from gcloud ADC; its scopes are those of the last `application-default login`. */
export const mintToken = (gcloud) => execFileSync(gcloud, ADC_ARGS, { stdio: ['ignore', 'pipe', 'ignore'], timeout: 60000 }).toString().trim();

/** The command line; returns the exit code (0 ok, 4 stopped, 2 usage or an unusable token). Injectable for tests. */
export async function cli(argv, { fetchImpl = fetch, mint = mintToken, out = console.log, err = console.error } = {}) {
  const i = argv.indexOf('--gcloud');
  if (i < 0 || !argv[i + 1]) { err('usage: adc-preflight.mjs --gcloud <path>'); return 2; }
  const token = mint(argv[i + 1]);
  if (!/^[\x21-\x7e]{20,4096}$/.test(token)) { err('ADC token has an unexpected shape'); return 2; }
  const verdict = await adcPreflight(fetchImpl, token);
  out(JSON.stringify(verdict));
  return verdict.ok ? 0 : 4;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  cli(process.argv.slice(2)).then((code) => { process.exitCode = code; }, () => { console.error('adc-preflight failed'); process.exitCode = 2; });
}
