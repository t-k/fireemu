// LP profile page: the same actor and case sequence as the Node WS profile, run inside Chromium with forceLongPolling. Rows are emitted live through a Playwright binding (not a route).
import * as A from '/firebase-app.js';
import * as D from '/firebase-database.js';
import { createActor } from '/actor.mjs';
import { runCases } from '/sequence.mjs';
window.__run = async cfg => {
  const actors = {};
  try {
    for (const role of ['writer', 'observer']) {
      actors[role] = createActor({ ...cfg, role }, D, A);
      D.onValue(D.ref(D.getDatabase(A.getApp(`packet-${role}`)), '.info/connected'), s => globalThis.__emit({ kind: 'sdk-event', role, event: s.val() ? 'connected' : 'disconnected' }));
    }
    return await runCases(actors, { caseMs: cfg.caseMs, onCase: row => globalThis.__emit({ kind: 'case', ...row }) });
  } finally { for (const actor of Object.values(actors)) await Promise.race([actor.close().catch(() => {}), new Promise(r => setTimeout(r, cfg.closeMs))]); }
};
window.__ready = true;
