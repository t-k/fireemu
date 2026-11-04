// The read-only A2 read-back of the events/admin/rest/rules/tokens suites (Opus presend review of packet 1 v1, Must 1).
//   node readback via observer.mjs: observer.mjs readback --run-dir <finished run dir> --production-config <file> --out <new dir>
// After a run that left an unknown outcome (exit 3, `unverified`), the coordinator reads the prefix, the Rules and the instance back
// at least ten minutes after the run ended. This sends the tokeninfo POST and three GETs, nothing else; it takes no lease and
// writes only its own output directory. The approval line of the run (script sha, cap, prefix, suite) must still stand.
import { mkdirSync, readFileSync, openSync, writeSync, closeSync, constants } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { adcVerdict, checkApproval, createAdmin, writeAll, createCounter, createJournal, mintToken, scriptManifest, sha256, targetUrls } from './lib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const READBACK_SUITES = ['events', 'admin', 'events+admin', 'rest', 'rules', 'tokens'];
export const WAIT_MS = 10 * 60 * 1000;

/** The admin REST of the run, narrowed to GET: any other method is refused before it reaches the network. */
export function readOnlyAdmin(admin) {
  return { unknownMutations: [], async rest(label, method, url, extra) { if (method !== 'GET') throw new Error(`read-only: ${method} refused`); return admin.rest(label, method, url, extra); } };
}

function finishedRun(runDir) {
  let result;
  try { result = JSON.parse(readFileSync(path.join(runDir, 'result.json'), 'utf8')); } catch (error) { throw new Error(`run directory: result.json unreadable (${error.code ?? error.name})`); }
  const bad = reason => new Error(`run directory: ${reason}`);
  if (result?.target !== 'production') throw bad('not a production run');
  if (!READBACK_SUITES.includes(result.suite)) throw bad('not an events, admin, rest, rules or tokens suite run');
  if (typeof result.runId !== 'string' || !/^[A-Za-z0-9-]{4,64}$/.test(result.runId)) throw bad('run id');
  if (typeof result.prefix !== 'string' || !/^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(result.prefix)) throw bad('prefix is not recorded');
  if (typeof result.endedAt !== 'string' || !Number.isFinite(Date.parse(result.endedAt))) throw bad('endedAt is not recorded');
  if (!Number.isSafeInteger(result.caps?.direct)) throw bad('direct cap is not recorded');
  return result;
}

/**
 * @returns {{exit: 0|1|3, report: object}} 0 settled (prefix null, Rules at baseline, instance ACTIVE), 1 not settled (data, other Rules,
 * instance not ACTIVE: a recovery packet, reviewed first), 3 unknown (a read failed or answered outside 200).
 */
export async function readback({ runDir, outDir, target, ledgerText }, deps = {}) {
  const d = { fetchImpl: fetch, mint: mintToken, now: () => Date.now(), write: undefined, ...deps };
  const result = finishedRun(runDir), script = scriptManifest(HERE).sha256;
  if (result.scriptSha256 !== script) throw new Error('run directory: the run was made by another script version');
  checkApproval(ledgerText, { runId: result.runId, scriptSha256: script, directCap: result.caps.direct, prefix: result.prefix, suite: result.suite });
  if (d.now() < Date.parse(result.endedAt) + WAIT_MS) throw new Error(`the read-back is allowed ten minutes after the run ended (${result.endedAt})`);
  mkdirSync(outDir, { mode: 0o700 });
  const journal = createJournal(path.join(outDir, 'journal.jsonl')), counter = createCounter({ direct: 8, reserve: 0 });
  try {
    counter.take('adc', 'adc'); const token = d.mint(target.gcloud);
    if (!/^[\x21-\x7e]{20,4096}$/.test(token)) throw new Error('ADC token shape');
    journal.addSecret(token); counter.take('tokeninfo');
    const verdict = await adcVerdict(d.fetchImpl, token, target.principalSha256);
    if (!verdict.ok) throw new Error(verdict.reason);
    const admin = readOnlyAdmin(createAdmin({ headers: { authorization: `Bearer ${token}`, 'x-goog-user-project': target.projectId }, journal, counter, fetchImpl: d.fetchImpl, timeoutMs: 10000 })), urls = targetUrls(target);
    const read = async (label, url) => { try { return await admin.rest(label, 'GET', url); } catch { return null; } };
    const [instance, rules, prefix] = [await read('instance', urls.instance), await read('rules', urls.data('.settings/rules')), await read('prefix', urls.data(result.prefix.slice(1)))];
    const checks = {
      prefix: prefix?.status === 200 ? (prefix.text.trim() === 'null' ? 'null' : 'data') : 'unknown',
      rules: rules?.status === 200 ? (sha256(rules.text) === target.baselineRulesSha256 ? 'baseline' : 'differs') : 'unknown',
      instance: (() => { if (instance?.status !== 200) return 'unknown'; try { const v = JSON.parse(instance.text); return v.type === 'USER_DATABASE' && v.state === 'ACTIVE' && String(v.name).endsWith(`/instances/${target.namespace}`) ? 'ACTIVE' : 'not-active'; } catch { return 'unknown'; } })(),
    };
    const unknown = Object.values(checks).includes('unknown'), settled = checks.prefix === 'null' && checks.rules === 'baseline' && checks.instance === 'ACTIVE';
    const exit = unknown ? 3 : settled ? 0 : 1;
    const report = { runId: result.runId, suite: result.suite, scriptSha256: script, prefix: result.prefix, endedAt: result.endedAt, readAt: new Date(d.now()).toISOString(), checks, verdict: unknown ? 'unknown' : settled ? 'settled' : 'not-settled', exit, counts: counter.used() };
    const fd = openSync(path.join(outDir, 'readback.json'), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { writeAll(fd, `${JSON.stringify(report, null, 2)}\n`, d.write); } finally { closeSync(fd); }
    return { exit, report };
  } finally { try { journal.close(); } catch { /* disk */ } }
}
