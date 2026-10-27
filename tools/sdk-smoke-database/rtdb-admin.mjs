// The RTDB management and data-plane administration that a production recorder runs around its scenarios,
// lifted out of rtdb-residual.mjs without a change of behaviour (the code between the markers is the code
// that file had; production-5 of the residual recorder was recorded with the pre-lift file, b3798ef8b).
// It sets up and retires the sandbox RTDB instance (API enable and disable, undelete, reenable, disable,
// delete), installs and restores Rules, deletes the run prefix, retries the propagation refusals of read-only
// GETs within a bounded total, and never re-sends a mutation whose answer is unknown (sticky `unresolved`).
//
//   const admin = createRtdbAdmin({ instance, location, caps, propagationMs, fireGraceMs, rulesFor });
//   admin.setupProduction(run, sleep); admin.installRules(run, o); ... admin.cleanup(run, o, sleep);
//
// `run` is the recorder's run object: { admin (the CV11 admin client), call, u (urls), state, unresolved,
// errors, propagation, propagationWaited, baseline, fireWait, sleep }.
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

const sha256 = (s) => createHash('sha256').update(s).digest('hex');
/** A step that ended the run's work on purpose: the recorder reports its message and cleans up. */
export class Stop extends Error {}

export function createRtdbAdmin({ instance: INSTANCE, location: LOCATION, caps: CAPS, propagationMs: PROPAGATION_MS, fireGraceMs: FIRE_GRACE_MS, rulesFor }) {
  // ---- begin of the code lifted from rtdb-residual.mjs ----
  function urls(o) {
    if (o.mode === 'local') {
      const q = `?ns=${o.local.ns}`;
      return { data: (p) => `${o.local.db}/${p}.json${q}` };
    }
    const n = o.packet.projectNumber, mgmt = `https://firebasedatabase.googleapis.com/v1beta/projects/${n}/locations`;
    return {
      data: (p) => `https://${INSTANCE}.firebaseio.com/${p}.json`,
      service: `https://serviceusage.googleapis.com/v1/projects/${n}/services/firebasedatabase.googleapis.com`, serviceName: `projects/${n}/services/firebasedatabase.googleapis.com`,
      op: (name) => `https://serviceusage.googleapis.com/v1/${name}`, list: `${mgmt}/-/instances`,
      instance: `${mgmt}/${LOCATION}/instances/${INSTANCE}`, instanceName: `projects/${n}/locations/${LOCATION}/instances/${INSTANCE}`,
    };
  }

  /**
   * The data host's answer to a request right after the reenable: 423 with exactly this error (recorded in production-4,
   * 97 bytes). Anything else, another status or another text, is not read as the reenable still propagating.
   */
  function isDisabledByOwner(status, text) {
    if (status !== 423) return false;
    let doc;
    try { doc = JSON.parse(text); } catch { return false; }
    return !!doc && typeof doc === 'object' && Object.keys(doc).length === 1 && doc.error === `The Firebase database '${INSTANCE}' has been disabled by a database owner.`;
  }

  // The run's view of what it owns. state.* is 'baseline' or 'ours' ('unknown' after an unknown answer);
  // unresolved holds unknown creates and deletes: sticky, never re-sent. (Same flow as the CV11 recorder.)
  async function read(run, step, method, url, accept, body) {
    const options = { raw: method === 'GET' && url.includes('.settings/rules') };
    let r = await run.call(step, method, url, body, options);
    // Bounded backoff 2, 4, 8, 16, 30, 30, 30 s (120 s in all), counted against the caps; GETs only.
    // 423 (production-4, 2026-10-27): the data host still sees the instance as disabled for a moment after the reenable
    // although the Rules endpoint already answers; only that exact body counts, see isDisabledByOwner.
    // 403: the management API list right after the enable (CV11 production-1, propagation). 401 is retried too; it is
    // harmless, but the 401 of this recorder's production-1 and production-2 was a credential cause (an ADC token
    // without userinfo.email, which adc-preflight.mjs now refuses before any request), not propagation.
    for (let k = 1; method === 'GET' && run.propagation && r.outcome === 'refused' && (r.status === 403 || r.status === 401 || isDisabledByOwner(r.status, r.text)); k++) {
      const wait = Math.min(2000 * 2 ** (k - 1), 30000, PROPAGATION_MS - run.propagationWaited);
      if (wait <= 0) break;
      run.propagationWaited += wait;
      await run.sleep(wait);
      r = await run.call(`${step}-retry-${k}`, method, url, body, options);
    }
    if (r.outcome !== 'ok' || !accept(r.value, r.text)) throw new Stop(`${step}: ${r.outcome}`);
    return r.value ?? r.text;
  }
  async function mutate(run, step, key, method, url, body, accept = () => true, sticky = true) {
    const r = await run.call(step, method, url, body);
    if (r.outcome === 'refused') throw new Stop(`${step}: refused`);
    if (r.outcome === 'unknown' || !accept(r.value)) {
      if (key) run.state[key] = 'unknown';
      if (sticky) run.unresolved.push({ step, key });
      throw new Stop(`${step}: unknown`);
    }
    return r.value;
  }
  async function waitOperation(run, step, op, sleep) {
    for (let i = 0; op?.done !== true; i++) {
      if (i >= CAPS.pollsPerOperation) return false;
      await sleep(5000);
      const r = await run.call(`${step}-poll-${i}`, 'GET', run.u.op(op.name));
      if (r.outcome !== 'ok' || r.value?.name !== op.name) return false;
      op = r.value;
    }
    return !op.error;
  }
  const isInstance = (run, state) => (v) => v?.name === run.u.instanceName && v.type === 'USER_DATABASE' && v.state === state;

  async function setApi(run, verb, sleep) {
    const op = await mutate(run, `api-${verb}`, 'api', 'POST', `${run.u.service}:${verb}`, {}, (v) => /^operations\//.test(v?.name));
    run.state.api = verb === 'enable' ? 'ours' : 'unknown'; // acknowledged: no longer the starting state until read back
    if (!(await waitOperation(run, `api-${verb}`, op, sleep))) { run.state.api = 'unknown'; run.unresolved.push({ step: `api-${verb}`, key: 'api' }); throw new Stop(`api-${verb}: operation`); }
    const want = verb === 'enable' ? 'ENABLED' : 'DISABLED';
    await read(run, `api-${want.toLowerCase()}`, 'GET', run.u.service, (v) => v?.name === run.u.serviceName && v.state === want);
    run.state.api = verb === 'enable' ? 'ours' : 'baseline';
  }

  async function setupProduction(run, sleep) {
    const u = run.u;
    await read(run, 'api-before', 'GET', u.service, (v) => v?.name === u.serviceName && v.state === 'DISABLED');
    await setApi(run, 'enable', sleep);
    run.propagation = true;
    await read(run, 'instance-before', 'GET', u.instance, isInstance(run, 'DELETED'));
    await read(run, 'active-before', 'GET', u.list, (v) => !v?.instances?.length && !v?.nextPageToken);
    const back = await mutate(run, 'instance-undelete', 'instance', 'POST', `${u.instance}:undelete`, undefined, (v) => isInstance(run, 'ACTIVE')(v) || isInstance(run, 'DISABLED')(v));
    run.state.instance = 'ours';
    if (back.state === 'DISABLED') await mutate(run, 'instance-reenable', 'instance', 'POST', `${u.instance}:reenable`, undefined, isInstance(run, 'ACTIVE'));
    await read(run, 'instance-active', 'GET', u.instance, isInstance(run, 'ACTIVE'));
  }

  /** Installs the Rules (open or deny) and reads them back; the first install also checks the baseline. */
  async function putRules(run, step, want) {
    const rulesUrl = run.u.data('.settings/rules');
    run.state.rules = 'ours';
    await mutate(run, `${step}-put`, 'rules', 'PUT', rulesUrl, want, (v) => v?.status === 'ok', false);
    await read(run, `${step}-read`, 'GET', rulesUrl, (_, text) => { try { return isDeepStrictEqual(JSON.parse(text), want); } catch { return false; } });
  }
  async function installRules(run, o) {
    const rulesUrl = run.u.data('.settings/rules');
    run.baseline = await read(run, 'rules-before', 'GET', rulesUrl, (_, text) => !o.packet || sha256(text) === o.packet.baselineRulesSha256);
    await read(run, 'prefix-before', 'GET', run.u.data(o.prefix), (v) => v === null);
    run.state.data = 'ours';
    await putRules(run, 'rules-install', rulesFor(o.prefix));
  }

  async function cleanup(run, o, sleep) {
    run.admin.cleanup();
    const steps = [
      async () => {
        if (run.state.data === 'baseline') return;
        // Pending onDisconnect writes of an unfinished cv10 profile would recreate data after the delete.
        if (run.fireWait) await sleep(FIRE_GRACE_MS);
        await mutate(run, 'prefix-delete', 'data', 'DELETE', run.u.data(o.prefix), undefined, (v) => v === null);
        await read(run, 'prefix-null', 'GET', run.u.data(o.prefix), (v) => v === null);
        run.state.data = 'baseline';
      },
      async () => {
        if (run.state.rules === 'baseline') return;
        await mutate(run, 'rules-restore', null, 'PUT', run.u.data('.settings/rules'), run.baseline, (v) => v?.status === 'ok', false);
        await read(run, 'rules-restored', 'GET', run.u.data('.settings/rules'), (_, text) => text === run.baseline);
        run.state.rules = 'baseline';
      },
      async () => {
        if (o.mode !== 'production' || run.state.instance !== 'ours' || run.state.rules !== 'baseline' || run.state.data !== 'baseline') return;
        await mutate(run, 'instance-disable', 'instance', 'POST', `${run.u.instance}:disable`, undefined, isInstance(run, 'DISABLED'));
        await read(run, 'instance-disabled', 'GET', run.u.instance, isInstance(run, 'DISABLED'));
        await mutate(run, 'instance-delete', 'instance', 'DELETE', run.u.instance, undefined, isInstance(run, 'DELETED'));
        await read(run, 'instance-deleted', 'GET', run.u.instance, isInstance(run, 'DELETED'));
        await read(run, 'active-after', 'GET', run.u.list, (v) => !v?.instances?.length && !v?.nextPageToken);
        run.state.instance = 'baseline';
      },
      async () => { if (run.state.api === 'ours' && run.state.instance === 'baseline') await setApi(run, 'disable', sleep); },
    ];
    for (const step of steps) try { await step(); } catch (e) { run.errors.push(e instanceof Stop ? e.message : `unexpected: ${e?.message}`); }
  }
  // ---- end of the code lifted from rtdb-residual.mjs ----
  return { urls, isDisabledByOwner, read, mutate, waitOperation, isInstance, setApi, setupProduction, putRules, installRules, cleanup };
}
