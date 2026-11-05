import { CapExceeded, sha256, unknownStatus } from './lib.mjs';

export const RULES_LOAD_PROFILES = ['r1-rules-load', 'r2-rules-load'];
export const TABLE = [
  { id: 'g-dup-key', body: '{"rules":{"a":{".read":"v0"},"a":{".read":"v1"}}}' },
  { id: 'g-dup-read', body: '{"rules":{".read":"v0",".read":"v1"}}' },
  { id: 'h-dup-indexOn', body: '{"rules":{".indexOn":"a",".indexOn":"b"}}' },
  { id: 'e-index-root-dot', body: '{"rules":{".indexOn":"a.b"}}' },
  { id: 'e-index-root-dollar', body: '{"rules":{".indexOn":"$x"}}' },
  { id: 'e-index-root-empty', body: '{"rules":{".indexOn":""}}' },
  { id: 'h-index:"a//b"', body: '{"rules":{".indexOn":"a//b"}}' },
];
export const RULES_LOAD_CASES = TABLE.map(c => c.id);

export async function runRulesLoadProfile({ send, url, baselineText, emit = () => {}, cancelled = () => false, canSend = () => true }) {
  const rows = [], rulesUrl = url('.settings/rules.json', '');
  for (const spec of TABLE) {
    if (cancelled() || !canSend()) break;
    let answer, outcome = 'answered';
    try { answer = await send(spec.id, 'PUT', rulesUrl, { body: spec.body, record: true }); }
    catch (error) { outcome = error instanceof CapExceeded ? 'not-sent' : 'unknown'; }
    if (answer && (unknownStatus(answer.status) || answer.utf8 === false || answer.clipped)) outcome = 'unknown';
    if (answer && answer.status !== 200 && answer.status !== 400) outcome = 'unknown';
    const row = { kind: 'case', suite: 'rules-load', id: spec.id, ok: outcome === 'answered', outcome, requestBody: spec.body, ...(answer ? { status: answer.status, body: answer.text, bodyBytes: answer.bodyBytes, utf8: answer.utf8, clipped: answer.clipped, responseHeaders: answer.headers ?? {} } : {}), ...(outcome === 'unknown' ? { unknown: [spec.id] } : {}) };
    rows.push(row);
    if (outcome === 'unknown' || (answer?.status >= 200 && answer.status < 300)) {
      try {
        const restored = await send(`restore-${spec.id}`, 'PUT', rulesUrl, { body: baselineText });
        const readback = await send(`readback-${spec.id}`, 'GET', rulesUrl, {});
        if (restored.status !== 200 || readback.status !== 200 || sha256(readback.text) !== sha256(baselineText)) throw Error('restore not verified');
      } catch { row.ok = false; row.outcome = 'restore-unverified'; row.unknown = [spec.id]; emit(row); return rows; }
    }
    emit(row);
    if (outcome !== 'answered') break;
  }
  return rows;
}
