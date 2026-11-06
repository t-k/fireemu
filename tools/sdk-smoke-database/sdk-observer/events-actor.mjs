// The fixed cases of the events suite (G6): data, listeners and steps as SDK calls only. Shared by the Node WebSocket
// profile and the Chromium long-polling page; events-sequence.mjs runs them and records what the SDK reports.
// Paths are relative to the profile scope. `w(path)` is a reference on the writer's connection, `o(path)` on the observer's.
export const EVENT_CASES = ['key_window', 'priority_window', 'value_range', 'equal_events', 'cursor_pair', 'fanout', 'transactions', 'get_exists'];
export const CHILD_KINDS = ['value', 'child_added', 'child_changed', 'child_moved', 'child_removed'];

/** One `set` of the scope seeds every case except the priority window. */
export const SEED = {
  kw: { b: 1, c: 1, d: 1, e: 1 },
  vr: { a: 1, b: 5, c: 9 },
  eq: { p: { t: 1 }, q: { t: 2 } },
  cp: { a: { s: 1 }, b: { s: 1 }, c: { s: 1 }, d: { s: 2 } },
  fo: { x: { n: 1 }, y: { n: 1 }, z: 1 },
  tb: { v: 7 },
  tc: { n: 1 },
  ge: { a: 1, b: 2, c: 3 },
};
/** [child, value, priority], each written with setWithPriority under pw. */
export const PRIORITY_SEED = [['x', 1, 1], ['y', 2, 2], ['z', 3, 3], ['w', 4, 4]];

export function eventCases(D) {
  const q = (...constraints) => ref => D.query(ref, ...constraints);
  const listen = (label, path, query, kinds = CHILD_KINDS) => ({ label, path, query, kinds });
  const write = (label, run) => ({ kind: 'write', label, run });
  const get = (label, run) => ({ kind: 'get', label, run });
  const attach = { kind: 'attach', label: 'attach' };
  return [
    {
      id: 'key_window',
      listeners: [listen('Q1', 'kw', q(D.orderByKey(), D.limitToFirst(2))), listen('Q2', 'kw', q(D.orderByKey(), D.limitToLast(2)))],
      steps: [attach, write('set-a', w => D.set(w('kw/a'), 1)), write('set-f', w => D.set(w('kw/f'), 1)), write('remove-a', w => D.remove(w('kw/a'))), write('set-b', w => D.set(w('kw/b'), 2))],
    },
    {
      id: 'priority_window',
      listeners: [listen('P', 'pw', q(D.orderByPriority(), D.limitToFirst(2)))],
      steps: [attach, write('priority-z-0', w => D.setPriority(w('pw/z'), 0)), write('priority-x-10', w => D.setPriority(w('pw/x'), 10)), write('add-v-1.5', w => D.setWithPriority(w('pw/v'), 5, 1.5)), write('remove-y', w => D.remove(w('pw/y')))],
    },
    {
      id: 'value_range',
      listeners: [listen('V', 'vr', q(D.orderByValue(), D.startAt(4), D.endAt(8)))],
      steps: [attach, write('set-a-6', w => D.set(w('vr/a'), 6)), write('set-b-20', w => D.set(w('vr/b'), 20)), write('set-c-5', w => D.set(w('vr/c'), 5)), write('remove-c', w => D.remove(w('vr/c')))],
    },
    {
      id: 'equal_events',
      listeners: [listen('T', 'eq', q(D.orderByChild('t'), D.equalTo(2)))],
      steps: [attach, write('set-p-t-2', w => D.set(w('eq/p/t'), 2)), write('set-q-t-3', w => D.set(w('eq/q/t'), 3)), write('set-p-t-2-again', w => D.set(w('eq/p/t'), 2)), write('set-p', w => D.set(w('eq/p'), { t: 2, u: 1 }))],
    },
    {
      id: 'cursor_pair',
      listeners: [listen('C', 'cp', q(D.orderByChild('s'), D.startAt(1, 'b'), D.endAt(1, 'c')))],
      steps: [get('get', o => D.get(D.query(o('cp'), D.orderByChild('s'), D.startAt(1, 'b'), D.endAt(1, 'c')))), attach, write('set-b2', w => D.set(w('cp/b2'), { s: 1 }))],
    },
    {
      id: 'fanout',
      listeners: [listen('FO', 'fo', null, ['value']), listen('FX', 'fo/x', null), listen('FY', 'fo/y', null, ['value'])],
      steps: [attach, write('update-root', w => D.update(w(''), { 'fo/x/n': 2, 'fo/y/n': 2, 'fo/z': 2 })), write('set-fo', w => D.set(w('fo'), { x: { n: 3 }, w: 1 }))],
    },
    {
      id: 'transactions',
      listeners: [listen('TA', 'ta', null, ['value']), listen('TB', 'tb', null, ['value']), listen('TC', 'tc', null, ['value'])],
      steps: [
        attach,
        { kind: 'transaction', label: 'absent', path: 'ta', update: () => 1 },
        { kind: 'transaction', label: 'abort', path: 'tb', update: () => undefined },
        { kind: 'transaction', label: 'object', path: 'tc', update: current => ({ n: (current?.n ?? 0) + 1 }) },
      ],
    },
    {
      id: 'get_exists',
      listeners: [],
      steps: [get('get-window', o => D.get(D.query(o('ge'), D.orderByKey(), D.limitToFirst(2)))), get('get-missing', o => D.get(o('ge/missing')))],
    },
  ];
}
