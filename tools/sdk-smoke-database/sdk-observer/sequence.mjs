// Shared by Node (WS profile) and the Chromium page (LP profile): the fixed case order of gen2's driveProfile, with a deadline on every await.
export class Timeout extends Error { constructor(label, ms) { super(`${label} timed out after ${ms} ms`); this.name = 'Timeout'; this.label = label; } }
export function withTimeout(ms, label, promise) {
  let timer;
  const guard = new Promise((_, reject) => { timer = setTimeout(() => reject(new Timeout(label, ms)), ms); });
  return Promise.race([Promise.resolve(promise), guard]).finally(() => clearTimeout(timer));
}
// [role, case id]: the observer reads first, then the writer changes things (gen2 drive-profile.mjs).
export const CASE_ORDER = [['observer', 'key_range'], ['observer', 'value_equal'], ['observer', 'priority_range'], ['writer', 'push'], ['writer', 'update'], ['writer', 'multipath'], ['writer', 'server_timestamp'], ['writer', 'increment']];
// actors[role].execute(id) -> value. onCase gets one row per finished case; a failure stops the profile (the actor refuses any later case anyway).
export async function runCases(actors, { caseMs = 15000, onCase = () => {} } = {}) {
  const call = async (role, id) => { const t0 = Date.now(); try { const value = await withTimeout(caseMs, `${role}:${id}`, actors[role].execute(id)); return { role, id, ok: true, value, ms: Date.now() - t0 }; } catch (error) { return { role, id, ok: false, error: `${error?.name}: ${error?.message}`, ms: Date.now() - t0 }; } };
  const rows = [];
  for (const [role, id] of [['writer', 'startup'], ['observer', 'startup'], ['writer', 'seed'], ...CASE_ORDER]) {
    const row = await call(role, id);
    if (id === 'startup' && row.ok && row.value !== null) { row.ok = false; row.error = 'Error: startup root is not empty'; }
    rows.push(row); onCase(row);
    if (!row.ok) break;
  }
  return rows;
}
