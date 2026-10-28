import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { installSdkNextWsGuard } from './rtdb-residual.mjs';

function setup(options = {}) {
  const c = vm.createContext({ URL, writes: [], options });
  vm.runInContext(`class Socket { static OPEN = 1; constructor(url) { this.url = url; this.readyState = 1; this.listeners = {}; } addEventListener(k, f) { (this.listeners[k] ??= []).push(f); } send(x) { if (this.throwSend) throw Error("native failure"); writes.push(x); } fire(k, e = {}) { for (const f of this.listeners[k] ?? []) f(e); } } globalThis.WebSocket = Socket;`, c);
  vm.runInContext(`(${installSdkNextWsGuard.toString()})({ host:'127.0.0.1:9000', namespace:'demo', base:'local/sdk/r1-ws', maxConnections:2, maxMessages:options.maxMessages ?? 50 })`, c);
  const run = (code) => vm.runInContext(code, c);
  return { c, run };
}
const mk = (id) => `new WebSocket('ws://127.0.0.1:9000/.ws?v=5&ns=demo')`;
const handshake = (socket, session) => `${socket}.fire('message',{data:JSON.stringify({t:'c',d:{t:'h',d:{h:'127.0.0.1:9000',s:'${session}',v:'5'}}})})`;
const establish = (run) => {
  run(`globalThis.a = ${mk(1)}; ${handshake('a','s1')}; globalThis.b = ${mk(2)}; ${handshake('b','s2')}; __sdkNextWsGuard.beginOperation('startup-w'); __sdkNextWsGuard.endOperation(); __sdkNextWsGuard.startupRead('w',null); __sdkNextWsGuard.beginOperation('startup-o'); __sdkNextWsGuard.endOperation(); __sdkNextWsGuard.startupRead('o',null); __sdkNextWsGuard.arm()`);
};
const sendMutation = (run, id = 7) => run(`__sdkNextWsGuard.beginOperation('seed'); a.send(JSON.stringify({t:'d',d:{r:${id},a:'p',b:{p:'/local/sdk/r1-ws',d:1}}}))`);
const ack = (run, id = 7, status = 'ok') => run(`a.fire('message',{data:JSON.stringify({t:'d',d:{r:${id},b:{s:'${status}',d:''}}})})`);
const completeAfterSeed = (run) => {
  const rest = [['push-a'], ['write-a','p'], ['read-a'], ['push-b'], ['write-b','p'], ['read-b'], ['update','m'], ['get-update-preserves-sibling'], ['replace','p'], ['get-set-replaces-node'], ['fanout','m'], ['get-atomic-multipath-final'], ['change','m'], ['move','m'], ['server-values','m'], ['get-server-values'], ['transaction-abort'], ['transaction-apply','p']];
  let id = 30;
  for (const [label, action] of rest) {
    run(`__sdkNextWsGuard.beginOperation(${JSON.stringify(label)})`);
    if (action) { const value = action === 'm' ? { [label]: 1 } : label; run(`a.send(JSON.stringify({t:'d',d:{r:${id},a:${JSON.stringify(action)},b:{p:'/local/sdk/r1-ws',d:${JSON.stringify(value)}}}}))`); ack(run, id++); }
    run('__sdkNextWsGuard.endOperation()');
  }
};


test('two distinct sessions and two actor reads precede arm and quiescent finish', () => {
  const { run } = setup(); establish(run); sendMutation(run); assert.throws(() => run('__sdkNextWsGuard.finish()'), /pending/i);
});

test('ACK permits terminal, no send or replacement after terminal', () => {
  const { run } = setup(); establish(run); sendMutation(run); ack(run); run('__sdkNextWsGuard.endOperation()'); completeAfterSeed(run); run('__sdkNextWsGuard.finish()');
  assert.throws(() => run(`a.send('0')`), /frozen|terminal/i);
  assert.throws(() => run(mk(3)), /frozen|terminal/i);
});

test('startup requires exact scope, distinct handshakes, successful actor reads and no early mutation', () => {
  for (const bad of ['ws://127.0.0.1:9000/.ws?v=5&ns=other', 'ws://other:9000/.ws?ns=demo', 'ws://127.0.0.1:9000/wrong?ns=demo']) {
    const { run } = setup(); assert.throws(() => run(`new WebSocket(${JSON.stringify(bad)})`), /scope|host|namespace/i);
  }
  {
    const { run } = setup(); run(`globalThis.a=${mk(1)}; ${handshake('a','same')}; globalThis.b=${mk(2)}; ${handshake('b','same')}; __sdkNextWsGuard.beginOperation('startup-w'); __sdkNextWsGuard.endOperation(); __sdkNextWsGuard.startupRead('w',null); __sdkNextWsGuard.beginOperation('startup-o'); __sdkNextWsGuard.endOperation(); __sdkNextWsGuard.startupRead('o',null)`);
    assert.throws(() => run('__sdkNextWsGuard.arm()'), /session/i);
  }
  {
    const { run } = setup(); run(`globalThis.a=${mk(1)}; ${handshake('a','s1')}`);
    assert.throws(() => sendMutation(run), /startup|arm/i);
  }
});

test('synchronous budget and unknown ACK latch prevent a later send', () => {
  const { c, run } = setup({ maxMessages: 1 }); establish(run); sendMutation(run);
  assert.throws(() => run(`a.send('0')`), /limit/i);
  assert.equal(c.writes.length, 1);
  assert.throws(() => run(`a.send('0')`), /frozen/i);
});

test('close, reset, shutdown, nonzero fragment count, binary and unknown controls fail closed', () => {
  for (const input of [{ event: 'close' }, { data: JSON.stringify({t:'c',d:{t:'r',d:'other'}}) }, { data: JSON.stringify({t:'c',d:{t:'s',d:'bye'}}) }, { data: '2' }, { data: new Uint8Array([1]) }, { data: JSON.stringify({t:'c',d:{t:'z',d:{}}}) }]) {
    const { c, run } = setup(); establish(run); sendMutation(run);
    c.input = input;
    run(`a.fire(input.event ?? 'message', input)`);
    assert.throws(() => run(`b.send('0')`), /frozen/i);
    assert.equal(c.writes.length, 1);
  }
});

test('failed mutation ACK and foreign path fail before next wire send', () => {
  { const { c, run } = setup(); establish(run); sendMutation(run); ack(run,7,'datastale'); assert.throws(() => run(`a.send('0')`), /frozen/i); assert.equal(c.writes.length, 1); }
  { const { c, run } = setup(); establish(run); run(`__sdkNextWsGuard.beginOperation('seed')`); assert.throws(() => run(`a.send(JSON.stringify({t:'d',d:{r:8,a:'p',b:{p:'/foreign',d:1}}}))`), /scope/i); assert.equal(c.writes.length, 0); }
});


test('an acknowledged mutation cannot be sent twice inside one source operation', () => {
  const { c, run } = setup(); establish(run); sendMutation(run); ack(run);
  assert.throws(() => run(`a.send(JSON.stringify({t:'d',d:{r:8,a:'p',b:{p:'/local/sdk/r1-ws',d:1}}}))`), /retransmit|mutation/i);
  assert.equal(c.writes.length, 1);
});

test('the same acknowledged mutation cannot be resent in a later source operation', () => {
  const { c, run } = setup(); establish(run); sendMutation(run); ack(run); run("__sdkNextWsGuard.endOperation(); __sdkNextWsGuard.beginOperation('push-a'); __sdkNextWsGuard.endOperation(); __sdkNextWsGuard.beginOperation('write-a')");
  assert.throws(() => run(`a.send(JSON.stringify({t:'d',d:{r:8,a:'p',b:{p:'/local/sdk/r1-ws',d:1}}}))`), /retransmit/i);
  assert.equal(c.writes.length, 1);
});

test('pinned production namespace host may omit ns without permitting another host', () => {
  const c = vm.createContext({ URL });
  vm.runInContext(`class Socket { static OPEN=1; constructor() { this.readyState=1; } addEventListener() {} send() {} } globalThis.WebSocket=Socket;`, c);
  vm.runInContext(`(${installSdkNextWsGuard.toString()})({host:'demo.firebaseio.com',namespace:'demo',base:'local/sdk/r1-ws',secure:true})`, c);
  assert.doesNotThrow(() => vm.runInContext(`new WebSocket('wss://demo.firebaseio.com/.ws?v=5')`, c));
  assert.throws(() => vm.runInContext(`new WebSocket('wss://other.firebaseio.com/.ws?v=5')`, c), /scope/i);
});


test('seeded PICT WS guard combinations retain before-wire safety', () => {
  const matrix = process.env.WS_GUARD_PICT;
  if (!matrix) return;
  const lines = readFileSync(matrix, 'utf8').trim().split(/\r?\n/);
  const header = lines.shift().split('\t');
  for (const line of lines) {
    const cells = line.split('\t');
    const axes = Object.fromEntries(header.map((key, i) => [key, cells[i]]));
    const { c, run } = setup({ maxMessages: axes.Budget === 'exhausted' ? 0 : 50 });
    if (axes.Phase === 'armed') establish(run);
    else run(`globalThis.a = ${mk(1)}`);
    if (axes.Threat === 'mutation') {
      if (axes.Phase === 'armed' && axes.Budget === 'available') { sendMutation(run); assert.equal(c.writes.length, 1, line); }
      else { assert.throws(() => sendMutation(run), undefined, line); assert.equal(c.writes.length, 0, line); }
    } else {
      if (axes.Threat === 'foreign') assert.throws(() => run(`new WebSocket('ws://other:9000/.ws?ns=demo')`));
      else if (axes.Threat === 'fragment') run(`a.fire('message',{data:'2'})`);
      else run(`a.fire('message',{data:JSON.stringify({t:'c',d:{t:'r',d:'other'}})})`);
      assert.throws(() => run(`a.send('0')`), undefined, line);
      assert.equal(c.writes.length, 0, line);
    }
  }
});

test('loss while awaiting mutation ACK is explicitly UNKNOWN and irreversible', () => {
  const { run } = setup(); establish(run); sendMutation(run); run(`a.fire('close')`);
  const state = run('__sdkNextWsGuard.status()');
  assert.equal(state.frozen, true);
  assert.equal(state.unknown, true);
  assert.equal(state.pending, 1);
  assert.throws(() => run(`new WebSocket('ws://127.0.0.1:9000/.ws?ns=demo')`), /frozen/i);
  assert.throws(() => run('__sdkNextWsGuard.finish()'), /pending/i);
});

test('unsolicited ACK and repeated request ID freeze before subsequent sends', () => {
  { const { run } = setup(); establish(run); run(`a.fire('message',{data:JSON.stringify({t:'d',d:{r:991,b:{s:'ok'}}})})`); assert.throws(() => run(`a.send('0')`), /frozen/i); }
  { const { run } = setup(); establish(run); sendMutation(run); ack(run); run('__sdkNextWsGuard.endOperation()'); assert.throws(() => run(`a.send(JSON.stringify({t:'d',d:{r:7,a:'g',b:{p:'/local/sdk/r1-ws'}}}))`), /request id reuse/i); }
});


test('native send throw freezes as unknown and prototype calls cannot bypass membership', () => {
  { const { c, run } = setup(); establish(run); run(`a.throwSend = true`); assert.throws(() => sendMutation(run), /native failure/); assert.equal(run('__sdkNextWsGuard.status().unknown'), true); assert.equal(c.writes.length, 0); assert.throws(() => run(`b.send('0')`), /frozen/i); }
  { const { run } = setup(); establish(run); assert.throws(() => run(`WebSocket.prototype.send.call({}, '0')`), /send refused/i); }
});

test('abrupt startup close, foreign handshake host and bad mutation path refuse before wire', () => {
  { const { run } = setup(); run(`globalThis.a=${mk(1)}; a.fire('close');`); assert.throws(() => run(mk(2)), /frozen/i); }
  { const { run } = setup(); run(`globalThis.a=${mk(1)}; a.fire('message',{data:JSON.stringify({t:'c',d:{t:'h',d:{h:'unapproved.example',s:'x',v:'5'}}})})`); assert.throws(() => run(mk(2)), /frozen/i); }
  { const { c, run } = setup(); establish(run); run(`__sdkNextWsGuard.beginOperation('seed')`); assert.throws(() => run(`a.send(JSON.stringify({t:'d',d:{r:7,a:'p',b:{p:'/local/sdk/r1-ws/../foreign',d:1}}}))`), /scope/i); assert.equal(c.writes.length, 0); }
});

test('terminal requires all nonmutating requests to settle too', () => {
  const { run } = setup(); establish(run); sendMutation(run); ack(run); run('__sdkNextWsGuard.endOperation()'); completeAfterSeed(run);
  run(`a.send(JSON.stringify({t:'d',d:{r:991,a:'n',b:{p:'/local/sdk/r1-ws/items'}}}))`);
  assert.equal(run('__sdkNextWsGuard.quiescent()'), false);
  assert.throws(() => run('__sdkNextWsGuard.finish()'), /quiescent/i);
});

test('both actor-specific startup reads are required before arm', () => {
  const { run } = setup();
  run(`globalThis.a=${mk(1)}; ${handshake('a','s1')}; globalThis.b=${mk(2)}; ${handshake('b','s2')}; __sdkNextWsGuard.beginOperation('startup-w'); __sdkNextWsGuard.endOperation(); __sdkNextWsGuard.startupRead('w',null); __sdkNextWsGuard.beginOperation('startup-o'); __sdkNextWsGuard.endOperation();`);
  assert.throws(() => run('__sdkNextWsGuard.arm()'), /startup/i);
  assert.throws(() => run(`a.send('0')`), /frozen/i);
});

test('rejected reads and foreign server pushes freeze before another send', () => {
  { const { run } = setup(); establish(run); run(`a.send(JSON.stringify({t:'d',d:{r:90,a:'g',b:{p:'/local/sdk/r1-ws'}}}))`); run(`a.fire('message',{data:JSON.stringify({t:'d',d:{r:90,b:{s:'permission_denied'}}})})`); assert.throws(() => run(`b.send('0')`), /frozen/i); }
  { const { run } = setup(); establish(run); run(`a.fire('message',{data:JSON.stringify({t:'d',d:{a:'d',b:{p:'/foreign',d:1}}})})`); assert.throws(() => run(`b.send('0')`), /frozen/i); }
});

test('child frames cannot open WebSockets outside the main guard budget', () => {
  const c = vm.createContext({ URL, window: { top: {} } });
  vm.runInContext(`class Socket { static OPEN=1; addEventListener() {} send() {} } globalThis.WebSocket=Socket;`, c);
  vm.runInContext(`(${installSdkNextWsGuard.toString()})({host:'127.0.0.1:9000',namespace:'demo',base:'local/sdk/r1-ws'})`, c);
  assert.throws(() => vm.runInContext(`new WebSocket('ws://127.0.0.1:9000/.ws?ns=demo')`, c), /child frame blocked/);
});

test('startup read receipts cannot be asserted before their corresponding operations', () => {
  const { run } = setup();
  run(`globalThis.a=${mk(1)}; ${handshake('a','s1')}; globalThis.b=${mk(2)}; ${handshake('b','s2')}`);
  assert.throws(() => run(`__sdkNextWsGuard.startupRead('w',null)`), /startup read/i);
  assert.throws(() => run('__sdkNextWsGuard.arm()'), /startup/i);
});

test('oversized outbound and inbound text fails before another native send', () => {
  { const { c, run } = setup(); establish(run); run(`__sdkNextWsGuard.beginOperation('seed')`); assert.throws(() => run(`a.send(JSON.stringify({t:'d',d:{r:7,a:'p',b:{p:'/local/sdk/r1-ws',d:'x'.repeat(17000)}}}))`), /size|oversize/i); assert.equal(c.writes.length, 0); }
  { const { c, run } = setup(); establish(run); run(`a.fire('message',{data:'x'.repeat(17000)})`); assert.throws(() => run(`b.send('0')`), /frozen/i); assert.equal(c.writes.length, 0); }
});
