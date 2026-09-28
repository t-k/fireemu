// Bounded collector for the FS-LISTEN-SDK observation cases.
//
// This module contains no Firebase import and opens no socket. Every effect is
// supplied through an injected dependency object, so the step machine, the
// budget, the invariant checks and the cleanup contract are all exercised by
// tests without a network. `listen_sdk_adapter.mjs` supplies the real
// dependencies.
//
// Secrets never reach this module. Passwords are read from a private file
// descriptor by the adapter and are not passed here; identity and refresh
// tokens are stripped by `redact` before anything is written to a receipt or a
// log line.

import { createHash } from 'node:crypto';

export const RECEIPT_SCHEMA = 'o6-listen-observation-v1';

const SECRET_KEY = /(password|secret|idtoken|id_token|accesstoken|access_token|refreshtoken|refresh_token|bearer|authorization|apikey|api_key|credential|assertion)/i;
const REDACTED = '[redacted]';

export const ok = value => ({ ok: true, value });
export const err = error => ({ ok: false, error });

/** Remove every secret-shaped key and any bearer-looking string value. */
export const redact = value => {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = SECRET_KEY.test(key) ? REDACTED : redact(item);
    }
    return out;
  }
  if (typeof value === 'string' && /^(Bearer\s|ey[A-Za-z0-9_-]{10,}\.)/.test(value)) {
    return REDACTED;
  }
  return value;
};

/** Refuse to start if a secret was passed on the command line. */
export const argvIsClean = (argv = []) =>
  argv.every(arg => !SECRET_KEY.test(arg) && !/^ey[A-Za-z0-9_-]{10,}\./.test(arg));

/**
 * A budget that bounds wall time and every chargeable operation. It is a
 * closure, not a class: `charge` either succeeds or returns the reason the
 * campaign envelope was exhausted.
 */
export const createBudget = ({ now, deadlineMs, limits }) => {
  const kinds = ['reads', 'writes', 'deletes', 'snapshots', 'listeners'];
  if (typeof now !== 'function' || !Number.isSafeInteger(deadlineMs) || deadlineMs <= 0) {
    throw new Error('finite positive budget duration required');
  }
  if (!limits || typeof limits !== 'object' || Array.isArray(limits) ||
      Object.keys(limits).length !== kinds.length || kinds.some(kind =>
        !Object.hasOwn(limits, kind) || !Number.isSafeInteger(limits[kind]) || limits[kind] < 0)) {
    throw new Error('every budget kind needs a finite nonnegative integer ceiling');
  }
  const ceilings = Object.freeze({ ...limits });
  const startedAt = now();
  if (!Number.isFinite(startedAt)) throw new Error('finite initial clock required');
  let lastNow = startedAt;
  let clockFailed = false;
  const used = { reads: 0, writes: 0, deletes: 0, snapshots: 0, listeners: 0 };
  const exceeded = [];
  const elapsedMs = () => {
    let current;
    try { current = now(); } catch { current = NaN; }
    if (!Number.isFinite(current) || current < lastNow) {
      clockFailed = true;
      exceeded.push('clock');
    } else if (!clockFailed) lastNow = current;
    return clockFailed ? deadlineMs : lastNow - startedAt;
  };
  const remainingMs = () => deadlineMs - elapsedMs();
  const charge = (kind, amount = 1) => {
    if (!Object.hasOwn(used, kind)) return err(`unknown-charge:${kind}`);
    if (!Number.isSafeInteger(amount) || amount <= 0) return err('invalid-charge-amount');
    if (remainingMs() <= 0) {
      exceeded.push('deadline');
      return err('deadline-exceeded');
    }
    const next = used[kind] + amount;
    if (!Number.isSafeInteger(next) || next > ceilings[kind]) {
      exceeded.push(kind);
      return err(`budget-exceeded:${kind}`);
    }
    used[kind] = next;
    return ok(next);
  };
  return {
    charge, remainingMs, elapsedMs,
    snapshot: () => ({
      used: { ...used }, limits: { ...ceilings }, deadlineMs,
      exceeded: [...new Set(exceeded)], exhausted: exceeded.length > 0,
    }),
  };
};

/** Recovery time is accumulated only while a recovery phase is running.
 * All passes share the same counters and elapsed time; resuming never refills
 * either reserve. A monotonic regression is latched, including between phases.
 * This measures time around awaited work; it does not cancel SDK operations.
 */
export const createRecoveryBudget = ({ now, deadlineMs, limits }) => {
  let last = now();
  if (!Number.isFinite(last)) throw new Error('finite initial recovery clock required');
  let elapsed = 0;
  let active = false;
  let failed = false;
  const clock = () => {
    let current;
    try { current = now(); } catch { current = NaN; }
    if (!Number.isFinite(current) || current < last) failed = true;
    if (!failed) {
      if (active) elapsed += current - last;
      last = current;
    }
    return failed ? NaN : elapsed;
  };
  const budget = createBudget({ now: clock, deadlineMs, limits });
  return {
    ...budget,
    charge: (...args) => active ? budget.charge(...args) : err('recovery-phase-not-active'),
    async withPhase(work) {
      if (active) throw new Error('recovery phase already active');
      clock();
      active = true;
      try {
        if (budget.remainingMs() <= 0) throw new Error('recovery deadline exhausted');
        return await work();
      }
      finally { budget.remainingMs(); active = false; }
    },
  };
};

/** Owned paths for a run nonce; mirrors campaign.owned_paths in Python. */
export const ownedPaths = (nonce, uid) => {
  if (!/^[0-9a-f]{32}$/.test(nonce ?? '')) throw new Error('nonce must be 128-bit lowercase hex');
  if (typeof uid !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(uid)) {
    throw new Error('safe uid is required to bind the private path');
  }
  const run = `o6_listen/${uid}/runs/${nonce}`;
  const docs = `${run}/docs`;
  return {
    run,
    alpha: `${docs}/alpha`,
    beta: `${docs}/beta`,
    gamma: `${docs}/gamma`,
    absent: `${docs}/absent`,
    private: `o6_listen_private/${uid}`,
  };
};

/**
 * The second principal's private document. It lives under the same Rules
 * pattern as `private`, so the only thing separating the two is the uid in the
 * path: exactly what the cross-identity cases observe.
 */
export const secondaryPaths = (nonce, uid) => {
  if (!/^[0-9a-f]{32}$/.test(nonce ?? '')) throw new Error('nonce must be 128-bit lowercase hex');
  if (typeof uid !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(uid)) {
    throw new Error('safe uid is required to bind the second private path');
  }
  return { privateB: `o6_listen_private/${uid}` };
};

/** Digest of an owned path, so a receipt never publishes a nonce or a uid. */
export const pathDigest = value => createHash('sha256').update(String(value)).digest('hex');

/** Marker written into every owned document so cleanup can prove ownership. */
export const ownerMarker = nonce => `o6-listen:${nonce}`;

export const normalizeDocumentSnapshot = (listener, snapshot, nameOf) => ({
  listener,
  snapshotKind: snapshot.first ? 'initial' : 'delta',
  changes: [],
  docs: snapshot.exists ? [nameOf(snapshot.path)] : [],
  exists: Boolean(snapshot.exists),
  fromCache: Boolean(snapshot.fromCache),
  hasPendingWrites: Boolean(snapshot.hasPendingWrites),
  error: null,
});

export const normalizeQuerySnapshot = (listener, snapshot, nameOf) => ({
  listener,
  snapshotKind: snapshot.first ? 'initial' : 'delta',
  changes: snapshot.changes.map(change => ({
    type: change.type,
    doc: nameOf(change.path),
    oldIndex: change.oldIndex,
    newIndex: change.newIndex,
  })),
  docs: snapshot.docs.map(nameOf),
  exists: null,
  fromCache: Boolean(snapshot.fromCache),
  hasPendingWrites: Boolean(snapshot.hasPendingWrites),
  error: null,
});

export const normalizeListenerError = (listener, error) => ({
  listener,
  snapshotKind: 'error',
  changes: [],
  docs: [],
  exists: null,
  fromCache: false,
  hasPendingWrites: false,
  error: typeof error?.code === 'string' ? error.code.replace(/^firestore\//, '') : 'unknown',
});

/**
 * Collapse a delta sequence into one aggregate row. A document that is added
 * and then only updated is reported once as added; a document present before
 * and after with a change is modified; a document that disappears is removed.
 * Index positions are not meaningful across a collapse and are recorded as null.
 */
export const aggregateChanges = (events, baseline = []) => {
  const present = new Set(baseline);
  const state = new Map();
  let docs = [...baseline];
  let fromCacheTransitions = [];
  for (const event of events) {
    if (event.snapshotKind === 'error') continue;
    fromCacheTransitions.push(event.fromCache);
    docs = [...event.docs];
    for (const change of event.changes) {
      const seen = state.get(change.doc);
      if (change.type === 'removed') {
        state.set(change.doc, present.has(change.doc) ? 'removed' : null);
      } else if (change.type === 'added') {
        state.set(change.doc, present.has(change.doc) ? 'modified' : seen === 'removed' ? 'modified' : 'added');
      } else {
        state.set(change.doc, seen === 'added' ? 'added' : 'modified');
      }
    }
  }
  const changes = [...state.entries()]
    .filter(([, type]) => type !== null)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([doc, type]) => ({ type, doc, oldIndex: null, newIndex: null }));
  // Collapse consecutive duplicates so the transition list records changes only.
  fromCacheTransitions = fromCacheTransitions.filter(
    (value, index, all) => index === 0 || all[index - 1] !== value,
  );
  return {
    listener: events[0]?.listener ?? 'primary',
    snapshotKind: 'aggregate',
    changes,
    docs,
    exists: null,
    fromCache: events.at(-1)?.fromCache ?? false,
    hasPendingWrites: events.at(-1)?.hasPendingWrites ?? false,
    error: null,
    fromCacheTransitions,
  };
};

const INVARIANTS = {
  'no-event-after-quiet-window': ctx =>
    ctx.eventsDuringQuiet === 0 ? null : 'a listener delivered an event inside the quiet window',
  'no-event-after-unsubscribe': ctx =>
    ctx.eventsAfterUnsubscribe === 0 ? null : 'a listener delivered an event after unsubscribe',
  'repeated-unsubscribe-is-a-no-op': ctx =>
    ctx.repeatedUnsubscribeThrew ? 'a repeated unsubscribe threw' : null,
  'no-event-after-listener-error': ctx =>
    ctx.eventsAfterError === 0 ? null : 'a listener delivered an event after its terminal error',
  'no-server-snapshot-before-error': ctx =>
    ctx.serverSnapshotsBeforeError === 0
      ? null
      : 'a server snapshot was delivered before the expected error',
  'no-duplicate-added-for-unchanged-document': ctx =>
    ctx.duplicateAdded.length === 0
      ? null
      : `resume re-added unchanged documents: ${ctx.duplicateAdded.join(',')}`,
  'from-cache-true-then-false-across-break': ctx =>
    ctx.fromCacheTransitions.includes(true) && ctx.fromCacheTransitions.at(-1) === false
      ? null
      : 'the listener never reported a cache-served window that recovered',
  'no-from-cache-transition': ctx =>
    ctx.fromCacheTransitions.filter(Boolean).length === 0
      ? null
      : 'the listener reported a cache-served window with no break',
  'terminal-document-set-complete': ctx =>
    ctx.terminalDocsComplete ? null : 'the terminal document set is missing an owned document',
};

/**
 * Drop events that differ from the event before them only in fields this case
 * does not compare. This reproduces what `onSnapshot` does by default when
 * `includeMetadataChanges` is false; the collector always subscribes with
 * metadata so it can tell when a listener has reached the server.
 */
export const collapseMetadataOnlyEvents = (events, comparedFields) => {
  if (!Array.isArray(comparedFields) || comparedFields.includes('fromCache')) return events;
  const project = row => JSON.stringify(comparedFields.map(field => row[field] ?? null));
  const kept = [];
  let previous = null;
  for (const row of events) {
    const key = project(row);
    if (key === previous) continue;
    previous = key;
    kept.push(row);
  }
  return kept;
};

export const checkInvariants = (names, ctx) => {
  const violations = [];
  for (const name of names) {
    const check = INVARIANTS[name];
    if (!check) {
      violations.push({ invariant: name, detail: 'unknown invariant' });
      continue;
    }
    const detail = check(ctx);
    if (detail) violations.push({ invariant: name, detail });
  }
  return violations;
};

/**
 * Cleanup is conditional on ownership. A document that is absent, or whose
 * owner marker does not match this run, is never deleted; the row records why.
 */
export const planCleanup = (paths, nonce) =>
  Object.entries(paths)
    .filter(([name]) => name !== 'run')
    .map(([name, path]) => ({ name, path, requiredMarker: ownerMarker(nonce) }));

const PROVEN_CLEANUP_OUTCOMES = [
  'deleted-and-absent',
  'not-created',
  'already-deleted-earlier',
];

export const classifyCleanup = rows => {
  const complete = rows.every(row => PROVEN_CLEANUP_OUTCOMES.includes(row.outcome));
  return {
    complete,
    rows,
    unproven: rows.filter(row => !PROVEN_CLEANUP_OUTCOMES.includes(row.outcome)),
    deleted: rows.filter(row => row.outcome === 'deleted-and-absent').length,
  };
};

// These are normalized adapter receipts, not raw SDK truthiness. A cached or
// pending local snapshot cannot prove that an owned server document is absent.
const cleanupSnapshot = value => {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      typeof value.exists !== 'boolean' ||
      (value.fromCache !== undefined && value.fromCache !== false) ||
      (value.hasPendingWrites !== undefined && value.hasPendingWrites !== false)) {
    throw new Error('invalid-cleanup-snapshot');
  }
  if (value.exists) {
    if (!value.fields || typeof value.fields !== 'object' || Array.isArray(value.fields)) {
      throw new Error('invalid-cleanup-fields');
    }
  } else if (value.fields != null || value.updateTime != null) {
    throw new Error('contradictory-cleanup-absence');
  }
  return value;
};

// Do not copy an arbitrary SDK exception message (which may contain credentials)
// into the public receipt. A short canonical code is sufficient for diagnosis.
const cleanupFailure = error =>
  typeof error?.code === 'string' && /^[a-zA-Z0-9_/-]{1,80}$/.test(error.code)
    ? error.code : 'cleanup-operation-failed';

export const runCleanup = async (deps, { client, paths, nonce, budget, clientFor = {} }) => {
  const rows = [];
  for (const target of planCleanup(paths, nonce)) {
    const row = { name: target.name, pathDigest: pathDigest(target.path),
      outcome: 'unattempted', detail: null };
    rows.push(row);
    // A document owned by the second principal can only be read and deleted
    // by the client signed in as that principal.
    const owner = clientFor[target.name] ?? client;
    const readCharge = budget.charge('reads');
    if (!readCharge.ok) {
      row.outcome = 'budget-exhausted'; row.detail = readCharge.error; continue;
    }
    let current;
    try {
      current = cleanupSnapshot(await deps.firestore.getDoc(owner, target.path));
      if (budget.remainingMs() <= 0) throw new Error('late-cleanup-read');
    } catch (error) {
      row.outcome = 'read-failed'; row.detail = cleanupFailure(error); continue;
    }
    if (current.exists === false) { row.outcome = 'not-created'; continue; }
    if (current.fields.owner !== target.requiredMarker) {
      row.outcome = 'not-owned'; row.detail = 'owner marker does not match this run'; continue;
    }
    // A client DocumentSnapshot exposes no updateTime precondition. The adapter
    // must instead re-read ownership inside a single-attempt transaction. Never
    // fall back to an unconditional delete if that operation is unavailable.
    if (typeof deps.firestore.deleteOwnedDoc !== 'function') {
      row.outcome = 'delete-failed'; row.detail = 'conditional-cleanup-unavailable'; continue;
    }
    const ownershipRead = budget.charge('reads');
    if (!ownershipRead.ok) {
      row.outcome = 'budget-exhausted'; row.detail = ownershipRead.error; continue;
    }
    const deleteCharge = budget.charge('deletes');
    if (!deleteCharge.ok) {
      row.outcome = 'budget-exhausted'; row.detail = deleteCharge.error; continue;
    }
    try {
      await deps.firestore.deleteOwnedDoc(owner, target.path, { owner: target.requiredMarker });
      if (budget.remainingMs() <= 0) throw new Error('late-cleanup-delete');
    } catch (error) {
      row.outcome = 'delete-failed'; row.detail = cleanupFailure(error); continue;
    }
    const absenceCharge = budget.charge('reads');
    if (!absenceCharge.ok) {
      row.outcome = 'absence-unverified'; row.detail = absenceCharge.error; continue;
    }
    try {
      const after = cleanupSnapshot(await deps.firestore.getDoc(owner, target.path));
      if (budget.remainingMs() <= 0) throw new Error('late-cleanup-absence');
      row.outcome = after.exists ? 'still-present' : 'deleted-and-absent';
    } catch (error) {
      row.outcome = 'absence-unverified'; row.detail = cleanupFailure(error);
    }
  }
  return classifyCleanup(rows);
};

const listenerNames = caseSpec => {
  const declared = new Map(caseSpec.listeners.map(listener => [listener.name, listener]));
  for (const step of caseSpec.steps) {
    if (step.kind === 'listen' && !declared.has(step.listener)) {
      declared.set(step.listener, { ...caseSpec.listeners[0], name: step.listener });
    }
  }
  return declared;
};

/**
 * Execute one observation case. Every effect goes through `deps`; the returned
 * record is a receipt fragment, never a verdict.
 */
export const runCase = async (deps, caseSpec, ctx) => {
  const { budget, nonce, paths, nameOf } = ctx;
  const specs = listenerNames(caseSpec);
  const registered = new Map();
  const closedListeners = new Set();
  const events = [];
  const counters = {
    eventsDuringQuiet: 0,
    eventsAfterUnsubscribe: 0,
    eventsAfterError: 0,
    serverSnapshotsBeforeError: 0,
    repeatedUnsubscribeThrew: false,
    duplicateAdded: [],
    fromCacheTransitions: [],
    terminalDocsComplete: true,
  };
  const failures = [];
  const seenDocs = new Set();
  let unsubscribed = false;
  let errored = false;
  let breakSeen = false;
  let baselineAt = 0;
  // Connectivity as the collector can actually observe it from the client SDK.
  // The Node SDK does not surface wire events, so each entry says what it was
  // derived from rather than claiming to be a transport frame.
  const transportTimeline = [];
  let connected = false;
  const note = (kind, derivedFrom) =>
    transportTimeline.push({ kind, atMs: deps.now(), derivedFrom });
  let allListenersClosed = true;
  const docsBeforeBreak = new Set();

  const record = row => {
    if (budget.charge('snapshots').ok === false) {
      failures.push('snapshot-budget-exhausted');
      return;
    }
    if (unsubscribed && row.listener === 'primary') counters.eventsAfterUnsubscribe += 1;
    if (errored && row.listener === 'primary') counters.eventsAfterError += 1;
    if (!errored && row.snapshotKind !== 'error' && row.fromCache === false) {
      counters.serverSnapshotsBeforeError += 1;
    }
    if (row.snapshotKind === 'error') errored = true;
    if (row.snapshotKind !== 'error' && row.fromCache === false) {
      const readCharge = budget.charge('reads', Math.max(row.docs.length, 1));
      if (!readCharge.ok) failures.push(readCharge.error);
    }
    if (row.snapshotKind !== 'error') {
      if (row.fromCache === false && !connected) {
        connected = true;
        note(breakSeen ? 'reconnect' : 'connect', 'first server-backed snapshot');
      } else if (row.fromCache === true && connected) {
        connected = false;
        note('disconnect', 'listener fell back to the local cache');
      }
      for (const change of row.changes) {
        if (change.type === 'added') {
          if (breakSeen && docsBeforeBreak.has(change.doc)) counters.duplicateAdded.push(change.doc);
          seenDocs.add(change.doc);
        }
      }
    }
    events.push(row);
  };

  const attach = name => {
    const spec = specs.get(name);
    if (!spec) throw new Error(`case ${caseSpec.caseId} has no listener named ${name}`);
    if (registered.has(name)) return;
    const charge = budget.charge('listeners');
    if (!charge.ok) {
      failures.push(charge.error);
      return;
    }
    // Where the initial snapshot ends depends on how the listener subscribed.
    //
    // With metadata changes, the same snapshot can be delivered from the cache
    // and then from the server, so the initial snapshot runs until the first
    // server-backed delivery and the cache-served prefix is part of it.
    //
    // Without metadata changes the SDK raises a callback only when data
    // changes, so every delivery after the first is a change: delivery order
    // decides, and a cache-served first callback does not make the following
    // data change part of the initial snapshot.
    const metadataMode = Boolean(spec.includeMetadataChanges);
    let seenServer = false;
    let delivered = 0;
    const options = { includeMetadataChanges: metadataMode };
    const onNext = snapshot => {
      const isInitial = metadataMode ? !seenServer : delivered === 0;
      delivered += 1;
      if (snapshot.fromCache === false) seenServer = true;
      const row =
        spec.kind === 'document'
          ? normalizeDocumentSnapshot(name, { ...snapshot, first: isInitial }, nameOf)
          : normalizeQuerySnapshot(name, { ...snapshot, first: isInitial }, nameOf);
      record(row);
    };
    const onError = error => record(normalizeListenerError(name, error));
    // A listener subscribes through the case client unless it names another
    // one (the second principal's own listener in the cross-identity control).
    const owner = ctx.clients?.[spec.client] ?? ctx.client;
    const unsubscribe =
      spec.kind === 'document'
        ? deps.firestore.onDocSnapshot(owner, paths[spec.target], options, onNext, onError)
        : deps.firestore.onQuerySnapshot(owner, { ...spec, parent: paths.run }, options, onNext, onError);
    registered.set(name, unsubscribe);
  };

  const write = async (clientName, doc, fields) => {
    const charge = budget.charge('writes');
    if (!charge.ok) {
      failures.push(charge.error);
      return;
    }
    await deps.firestore.setDoc(ctx.clients[clientName] ?? ctx.client, paths[doc], {
      ...fields,
      owner: ownerMarker(nonce),
    });
  };

  const waitFor = async predicate => {
    const started = deps.now();
    while (!predicate()) {
      if (budget.remainingMs() <= 0 || deps.now() - started > ctx.stepTimeoutMs) {
        failures.push('step-timeout');
        return false;
      }
      await deps.sleep(ctx.pollMs);
    }
    return true;
  };

  try {
    for (const step of caseSpec.steps) {
      if (budget.remainingMs() <= 0) {
        failures.push('deadline-exceeded');
        break;
      }
      switch (step.kind) {
        case 'seed':
        case 'write':
          await write(step.client ?? 'primary', step.doc, step.fields);
          break;
        case 'delete': {
          const charge = budget.charge('deletes');
          if (!charge.ok) {
            failures.push(charge.error);
            break;
          }
          await deps.firestore.deleteDoc(ctx.clients[step.client] ?? ctx.client, paths[step.doc], null);
          break;
        }
        case 'listen':
          attach(step.listener);
          break;
        case 'await': {
          const target = step.events;
          await waitFor(
            () =>
              events.slice(baselineAt).filter(row => row.listener === step.listener).length >=
              target,
          );
          break;
        }
        case 'baseline':
          baselineAt = events.length;
          break;
        case 'awaitServer':
          await waitFor(() => {
            const seen = events.filter(row => row.listener === step.listener);
            return seen.length > 0 && seen.at(-1).snapshotKind !== 'error' && seen.at(-1).fromCache === false;
          });
          break;
        case 'awaitError':
          await waitFor(() =>
            events.some(row => row.listener === step.listener && row.snapshotKind === 'error'),
          );
          break;
        case 'quiet': {
          const before = events.length;
          await deps.sleep(step.seconds * 1000);
          counters.eventsDuringQuiet += events.length - before;
          break;
        }
        case 'settle':
          await deps.sleep(step.seconds * 1000);
          break;
        case 'unsubscribe': {
          const unsubscribe = registered.get(step.listener);
          if (!unsubscribe) {
            if (step.repeat) counters.repeatedUnsubscribeThrew = true;
            break;
          }
          try {
            unsubscribe();
          } catch {
            if (step.repeat) counters.repeatedUnsubscribeThrew = true;
            allListenersClosed = false;
            failures.push(`unsubscribe-failed:${step.listener}`);
            // Retain the actual finalizer for the finally block; replacing a
            // failed unsubscribe with a no-op invents a closed listener.
            break;
          }
          if (!step.repeat) {
            unsubscribed = true;
            closedListeners.add(step.listener);
          }
          break;
        }
        case 'break':
          for (const doc of events.at(-1)?.docs ?? []) docsBeforeBreak.add(doc);
          breakSeen = true;
          note('break-requested', 'collector called disableNetwork');
          await deps.firestore.disableNetwork(ctx.client);
          break;
        case 'resume':
          note('resume-requested', 'collector called enableNetwork');
          await deps.firestore.enableNetwork(ctx.client);
          break;
        case 'signIn':
          await deps.auth.signIn(ctx.clients?.[step.client] ?? ctx.client, step.account);
          break;
        case 'signOut':
          await deps.auth.signOut(ctx.clients?.[step.client] ?? ctx.client);
          break;
        case 'revoke':
          // Out-of-band revocation of the client's current session, the way an
          // operator would do it from the Admin SDK. The adapter owns the
          // management call; the collector only records what the listener did.
          note('revoke-requested', 'collector asked the adapter to revoke the session');
          await deps.auth.revoke(ctx.clients?.[step.client] ?? ctx.client);
          break;
        default:
          failures.push(`unknown-step:${step.kind}`);
      }
    }
  } catch (error) {
    // A thrown step is recorded, never propagated: the caller still has to run
    // cleanup and write a receipt.
    failures.push(`step-threw:${cleanupFailure(error)}`);
  } finally {
    for (const [name, unsubscribe] of registered) {
      if (closedListeners.has(name)) continue;
      try {
        unsubscribe();
      } catch (error) {
        allListenersClosed = false;
        failures.push(`unsubscribe-failed:${name}:${cleanupFailure(error)}`);
      }
    }
    registered.clear();
  }

  let compared = events.slice(baselineAt);
  if (caseSpec.ignoreCachedPrefix) {
    const firstKept = compared.findIndex(
      row => row.snapshotKind === 'error' || row.fromCache === false,
    );
    compared = firstKept < 0 ? [] : compared.slice(firstKept);
  }
  if (caseSpec.collapseMetadataOnly !== false) {
    compared = collapseMetadataOnlyEvents(compared, caseSpec.comparedFields);
  }

  // Invariants describe the compared window, not the warm-up prefix.
  counters.fromCacheTransitions = compared
    .filter(row => row.snapshotKind !== 'error')
    .map(row => row.fromCache)
    .filter((value, index, all) => index === 0 || all[index - 1] !== value);
  const expectedDocs = new Set(
    caseSpec.expectedLocal.flatMap(event => event.docs).filter(Boolean),
  );
  const terminalDocs = new Set(compared.at(-1)?.docs ?? []);
  counters.terminalDocsComplete =
    caseSpec.comparison !== 'aggregate-changes' ||
    [...expectedDocs].every(doc => terminalDocs.has(doc));

  const observed =
    caseSpec.comparison === 'aggregate-changes'
      ? [aggregateChanges(compared, events[baselineAt - 1]?.docs ?? [])]
      : compared;

  return {
    caseId: caseSpec.caseId,
    role: caseSpec.role,
    comparison: caseSpec.comparison,
    complete: failures.length === 0,
    failures,
    observed: redact(observed),
    rawEvents: redact(events),
    rawEventCount: events.length,
    baselineAt,
    comparedFields: caseSpec.comparedFields ?? null,
    transportTimeline,
    invariantViolations: checkInvariants(caseSpec.invariants, counters),
    listenersClosed: allListenersClosed,
  };
};

/**
 * Run every case, then always run the final cleanup pass. Nothing thrown by a
 * case, by the per-case cleanup or by the caller's between-case hook escapes:
 * the thrown value is returned so the caller can record it on a receipt.
 */
export const runCatalog = async (
  deps,
  { catalog, contextFor, budget, cleanupBudget, paths, nonce, client, clientFor = {},
    betweenCases, beforeFinalCleanup },
) => {
  const caseRecords = [];
  const cleanupPasses = [];
  // Names this run has already deleted and proved absent, so the final pass can
  // say "already deleted earlier" instead of "never created".
  const deletedEarlier = new Set();
  const recordPass = (label, result) => {
    for (const row of result.rows) {
      if (row.outcome === 'deleted-and-absent') deletedEarlier.add(row.name);
      else if (row.outcome === 'not-created' && deletedEarlier.has(row.name)) {
        row.outcome = 'already-deleted-earlier';
      }
    }
    cleanupPasses.push({
      pass: label,
      complete: result.complete,
      deleted: result.rows.filter(row => row.outcome === 'deleted-and-absent').length,
      rows: result.rows,
    });
    return result;
  };
  let thrown = null;
  const recover = async (label, caseSpec = null) => {
    const work = async () => {
      let restorationFailure = null;
      try {
        if (caseSpec && betweenCases) await betweenCases(caseSpec);
        else if (!caseSpec && beforeFinalCleanup) await beforeFinalCleanup();
      }
      catch (error) { restorationFailure = cleanupFailure(error); }
      // A failed restoration does not prevent attempts on independent resources.
      const result = recordPass(label,
        await runCleanup(deps, { client, paths, nonce, budget: cleanupBudget, clientFor }));
      if (restorationFailure) thrown = thrown ?? restorationFailure;
      return result;
    };
    return typeof cleanupBudget.withPhase === 'function'
      ? cleanupBudget.withPhase(work) : work();
  };
  try {
    for (const caseSpec of catalog.cases) {
      caseRecords.push(await runCase(deps, caseSpec, contextFor(caseSpec)));
      await recover(caseSpec.caseId, caseSpec);
      if (thrown) break;
    }
  } catch (error) {
    thrown = cleanupFailure(error);
  }
  let cleanup;
  try {
    cleanup = await recover('final');
  } catch (error) {
    cleanup = classifyCleanup([{
      name: 'final-pass', pathDigest: null, outcome: 'cleanup-threw',
      detail: cleanupFailure(error),
    }]);
    thrown = thrown ?? cleanupFailure(error);
  }
  return {
    caseRecords,
    cleanup,
    cleanupPasses,
    // The final pass alone understates the run: most documents are deleted by
    // the per-case pass that follows the case which created them.
    totalDeleted: cleanupPasses.reduce((sum, pass) => sum + pass.deleted, 0),
    thrown,
  };
};

export const buildReceipt = ({
  campaign,
  campaignDigest,
  catalogDigest,
  environment,
  caseRecords,
  cleanup,
  cleanupPasses,
  totalDeleted,
  budget,
  cleanupBudget,
  thrown,
  productionExecuted,
}) => ({
  schema: RECEIPT_SCHEMA,
  caseId: campaign.caseId,
  campaignDigest,
  catalogDigest,
  productionExecuted: Boolean(productionExecuted),
  environment: redact(environment),
  budget: budget.snapshot(),
  cleanupBudget: cleanupBudget ? cleanupBudget.snapshot() : null,
  cleanup,
  cleanupPasses: cleanupPasses ?? null,
  totalDeleted: totalDeleted ?? null,
  thrown: thrown ?? null,
  cases: caseRecords,
  complete:
    caseRecords.every(record => record.complete && record.listenersClosed) &&
    cleanup.complete &&
    !budget.snapshot().exhausted &&
    !(cleanupBudget ? cleanupBudget.snapshot().exhausted : false) &&
    !thrown,
});
