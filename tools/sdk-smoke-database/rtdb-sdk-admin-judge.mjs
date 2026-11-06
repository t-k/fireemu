// The admin suite's (G13) part of the comparison: the step table and labels of sdk-observer/admin-suite.mjs, judged by
// the engine in rtdb-sdk-events-judge.mjs with the same fail-closed rules as the events suite.
// Admin-specific facts the record carries (and the engine compares exactly, as recorded):
// - push: only the key's shape is recorded (`push-id` = 20 characters of the push alphabet; `other-<length>` otherwise),
//   never the key, so no mask is needed; the pushed value is recorded and compared.
// - every case runs under Rules that deny every client (`.read:false`, `.write:false`); a production answer that shows
//   no bypass (an error in ack or result) is a recorded fact and is compared like any other value.
import { adminCases } from './sdk-observer/admin-suite.mjs';

const specs = adminCases();
/** case id -> [{kind, label}] in the recorder's order. */
export const ADMIN_STEPS = Object.fromEntries(specs.map(c => [c.id, c.steps.map(({ kind, label }) => ({ kind, label }))]));
/** case id -> the listener labels each list may carry. */
export const ADMIN_LABELS = Object.fromEntries(specs.map(c => [c.id, { observer: c.listeners.map(l => l.label), writer: c.steps.some(s => s.kind === 'transaction') ? ['W', 'txn'] : [] }]));
