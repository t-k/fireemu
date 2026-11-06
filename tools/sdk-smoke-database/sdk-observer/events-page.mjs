// LP profile page of the events suite: the same recorder as the Node WebSocket profile, run inside Chromium with
// forceLongPolling. Rows are emitted live through a Playwright binding (not a route).
import * as A from '/firebase-app.js';
import * as D from '/firebase-database.js';
import { runEventsProfile } from '/events-sequence.mjs';
window.__runEvents = cfg => runEventsProfile({ D, A, cfg, emit: row => globalThis.__emit(row) });
window.__ready = true;
