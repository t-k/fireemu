// node --test adc-preflight.test.mjs: the ADC scope verdict (pure), the tokeninfo request, and the command line.
import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { ADC_ARGS, API_SCOPES, EMAIL_SCOPE, TOKENINFO_URL, adcPreflight, adcScopeVerdict } from './adc-preflight.mjs';

const G = 'https://www.googleapis.com/auth/';
const EMAIL = 'owner@example.com';
// doc(scopes) has the email; doc(scopes, undefined) has no email field; doc(scopes, x) has x.
const doc = (scopes, ...e) => ({ scope: scopes.join(' '), ...((e.length ? e[0] : EMAIL) === undefined ? {} : { email: e.length ? e[0] : EMAIL }) });
const answer = (status, body) => async () => ({ status, text: async () => (typeof body === 'string' ? body : JSON.stringify(body)) });
const TOK = 'ya29.TESTTOKEN-not-real';

test('verdict: the 2026-10-26 ADC (androidpublisher and cloud-platform, no email) is refused and names the email scope and the email', () => {
  const v = adcScopeVerdict({ scope: `${G}androidpublisher ${G}cloud-platform` });
  assert.deepEqual(v, { ok: false, reason: 'adc-scopes-missing', missing: [`${G}userinfo.email`, 'email'] });
});

test('verdict: gcloud default-login shape and the re-login shape are accepted', () => {
  for (const scopes of [['openid', `${G}userinfo.email`, `${G}cloud-platform`, `${G}sqlservice.login`], ['openid', `${G}userinfo.email`, `${G}cloud-platform`, `${G}firebase.database`, `${G}androidpublisher`], [`${G}userinfo.email`, `${G}firebase.database`]]) {
    assert.deepEqual(adcScopeVerdict(doc(scopes)), { ok: true, missing: [] }, scopes.join(' '));
  }
});

test('verdict: each condition alone refuses, and the refusal names exactly what is missing', () => {
  assert.deepEqual(adcScopeVerdict(doc([`${G}cloud-platform`])).missing, [`${G}userinfo.email`]);
  assert.deepEqual(adcScopeVerdict(doc([`${G}userinfo.email`])).missing, [`${G}firebase.database or ${G}cloud-platform`]);
  assert.deepEqual(adcScopeVerdict(doc([`${G}userinfo.email`, `${G}cloud-platform`], '')).missing, ['email']);
  assert.deepEqual(adcScopeVerdict(doc([`${G}userinfo.email`, `${G}cloud-platform`], '   ')).missing, ['email']);
  assert.deepEqual(adcScopeVerdict(doc([`${G}userinfo.email`, `${G}cloud-platform`], undefined)).missing, ['email']);
  assert.deepEqual(adcScopeVerdict({ scope: `${G}userinfo.email ${G}cloud-platform`, email: 5 }).missing, ['email']);
  assert.deepEqual(adcScopeVerdict(doc([])).missing, [`${G}userinfo.email`, `${G}firebase.database or ${G}cloud-platform`]);
  assert.deepEqual([EMAIL_SCOPE, ...API_SCOPES], [`${G}userinfo.email`, `${G}firebase.database`, `${G}cloud-platform`]);
});

test('verdict: scopes are whole space-separated tokens: prefixes, suffixes and look-alikes do not count', () => {
  const near = [`${G}userinfo.email.readonly`, `${G}userinfo.profile`, `${G}xuserinfo.email`, 'userinfo.email', `${G}firebase`, `${G}firebase.database.readonly`, `${G}cloud-platform.read-only`, `${G}cloud-platform-extra`];
  for (const s of near) {
    assert.equal(adcScopeVerdict(doc([s, `${G}cloud-platform`])).ok, false, `${s} as the email scope`);
    assert.equal(adcScopeVerdict(doc([`${G}userinfo.email`, s])).ok, s === `${G}cloud-platform` ? true : false, `${s} as the api scope`);
  }
  assert.equal(adcScopeVerdict({ scope: `${G}userinfo.email\t${G}cloud-platform\n`, email: EMAIL }).ok, true, 'any whitespace separates');
});

test('verdict: an unusable answer is unverified, never ok', () => {
  for (const bad of [undefined, null, 5, 'x', [], {}, { scope: 5 }, { scope: null, email: EMAIL }, { email: EMAIL }]) {
    assert.deepEqual(adcScopeVerdict(bad), { ok: false, reason: 'adc-scopes-unverified', missing: [] }, JSON.stringify(bad));
  }
});

// Property (seeded): the verdict is ok exactly when the three conditions hold, over random scope sets and emails.
test('property: ok iff email scope, one api scope and a non-empty email; the verdict never holds the email', () => {
  let seed = 7;
  const rand = () => { seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const pool = [`${G}userinfo.email`, `${G}firebase.database`, `${G}cloud-platform`, `${G}androidpublisher`, 'openid', `${G}userinfo.profile`, `${G}userinfo.email.readonly`];
  const emails = [EMAIL, '', '  ', undefined];
  for (let i = 0; i < 300; i++) {
    const scopes = pool.filter(() => rand() < 0.5), email = emails[Math.floor(rand() * emails.length)];
    const want = scopes.includes(pool[0]) && (scopes.includes(pool[1]) || scopes.includes(pool[2])) && typeof email === 'string' && email.trim() !== '';
    const v = adcScopeVerdict(doc(scopes, email));
    assert.equal(v.ok, want, `${scopes.join(' ')} / ${JSON.stringify(email)}`);
    assert.equal(v.missing.length === 0, want);
    assert.ok(!JSON.stringify(v).includes('example.com'));
  }
});

test('request: one POST to tokeninfo with the token in the form body only, redirects not followed, nothing but the verdict returned', async () => {
  const seen = [];
  const f = async (url, init) => { seen.push({ url, init }); return answer(200, { ...doc([`${G}cloud-platform`]), aud: 'x', exp: '1' })(); };
  const v = await adcPreflight(f, TOK);
  assert.equal(v.ok, false);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].url, 'https://oauth2.googleapis.com/tokeninfo'); assert.equal(TOKENINFO_URL, seen[0].url);
  assert.equal(seen[0].init.method, 'POST'); assert.equal(seen[0].init.redirect, 'manual');
  assert.equal(seen[0].init.body, `access_token=${encodeURIComponent(TOK)}`);
  assert.deepEqual(seen[0].init.headers, { 'content-type': 'application/x-www-form-urlencoded' });
  assert.ok(seen[0].init.signal instanceof AbortSignal);
  assert.ok(!JSON.stringify(v).includes(TOK) && !JSON.stringify(v).includes('example.com') && !('scopes' in v));
  const ok = await adcPreflight(answer(200, doc(['openid', `${G}userinfo.email`, `${G}cloud-platform`])), TOK);
  assert.deepEqual(ok, { ok: true, missing: [] });
});

test('request: a non-2xx, a redirect, an unreadable body and a network failure are unverified even when the body would pass', async () => {
  const good = doc([`${G}userinfo.email`, `${G}cloud-platform`]);
  for (const f of [answer(400, good), answer(401, good), answer(302, good), answer(199, good), answer(300, good), answer(500, good), answer(200, 'not json'), answer(200, ''), answer(204, ''), async () => { throw new Error('network'); }]) {
    assert.deepEqual(await adcPreflight(f, TOK), { ok: false, reason: 'adc-scopes-unverified', missing: [] });
  }
  assert.equal((await adcPreflight(answer(201, good), TOK)).ok, true, 'any 2xx is an answer');
  assert.equal((await adcPreflight(answer(299, good), TOK)).ok, true);
});

test('the token is minted by gcloud ADC without a scopes argument', () => {
  assert.deepEqual(ADC_ARGS, ['auth', 'application-default', 'print-access-token']);
});

test('command line: needs --gcloud, and refuses a token of an unexpected shape before any request', () => {
  const run = (...args) => spawnSync(process.execPath, [new URL('./adc-preflight.mjs', import.meta.url).pathname, ...args], { encoding: 'utf8' });
  const none = run();
  assert.equal(none.status, 2); assert.match(none.stderr, /usage/);
  const dir = mkdtempSync(path.join(tmpdir(), 'adc-'));
  const fake = path.join(dir, 'gcloud');
  writeFileSync(fake, '#!/bin/sh\necho short\n'); chmodSync(fake, 0o755);
  const short = run('--gcloud', fake);
  assert.equal(short.status, 2); assert.match(short.stderr, /unexpected shape/); assert.equal(short.stdout, '');
});
