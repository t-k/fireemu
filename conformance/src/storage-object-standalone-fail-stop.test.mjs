import assert from "node:assert/strict";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const api = await import("./storage-object/production-standalone-fail-stop.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const moduleUrl = new URL("./storage-object/production-standalone-fail-stop.mjs", import.meta.url)
  .href;
const lockUrl = new URL("./storage-object/project-locks.mjs", import.meta.url).href;
const secret = "SYNTHETIC_STANDALONE_REASON_+/private";

function fixture(action) {
  assert.equal(typeof api.createProductionStandaloneFailStop, "function");
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "storage-object-fail-stop-")));
  fs.chmodSync(root, 0o700);
  const capture = join(root, "capture");
  fs.mkdirSync(capture, { mode: 0o700 });
  try {
    return action({ root, capture });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function child(
  { root, capture },
  { shape = "primitive", slot = 1, fault = "none", kind = "owner" } = {},
) {
  const source = `
    import fs from 'node:fs';
    import { syncBuiltinESMExports } from 'node:module';
    import { withProjectLocks } from ${JSON.stringify(lockUrl)};
    const root = ${JSON.stringify(root)}, directory = ${JSON.stringify(capture)};
    const shape = ${JSON.stringify(shape)}, slot = ${slot}, fault = ${JSON.stringify(fault)}, kind = ${JSON.stringify(kind)};
    let getters = 0, constructors = 0, unhandled = 0, calls = 0, fileSyncs = 0, directorySyncs = 0;
    const secret = ${JSON.stringify(secret)};
    process.on('unhandledRejection', () => { unhandled++; });
    process.on('exit', () => fs.writeFileSync(root + '/metrics.json', JSON.stringify({ getters, constructors, unhandled, calls, fileSyncs, directorySyncs }), { mode: 0o600 }));
    const originalFsync = fs.fsyncSync;
    fs.fsyncSync = fd => {
      const directory = fs.fstatSync(fd).isDirectory();
      if (directory) directorySyncs++; else fileSyncs++;
      if ((fault === 'file-fsync' && !directory) || (fault === 'directory-fsync' && directory)) throw new Error(secret);
      const uncertain = fault === 'started' ? root + '/started-attempt.json' : fault === 'terminal' ? root + '/terminal-attempt.json' : null;
      if (uncertain && fs.existsSync(uncertain) && fs.fstatSync(fd).ino === fs.statSync(uncertain).ino && fs.fstatSync(fd).dev === fs.statSync(uncertain).dev) throw new Error(secret);
      if (!directory && fault === 'hardlink') fs.linkSync(directoryPath + '/fatal-r1.json', root + '/fatal-alias');
      if (!directory && fault === 'replace-file') { fs.renameSync(directoryPath + '/fatal-r1.json', root + '/fatal-original'); fs.writeFileSync(directoryPath + '/fatal-r1.json', 'FOREIGN', { mode: 0o600 }); }
      originalFsync(fd);
    };
    const originalWrite = fs.writeSync;
    const directoryPath = directory;
    if (['write', 'zero-write', 'partial-write'].includes(fault)) fs.writeSync = (fd, ...args) => {
      const path = directory + '/fatal-r1.json';
      if (fs.existsSync(path) && fs.fstatSync(fd).ino === fs.statSync(path).ino && fs.fstatSync(fd).dev === fs.statSync(path).dev) {
        if (fault === 'write') throw new Error(secret);
        if (fault === 'zero-write') return 0;
        return originalWrite(fd, args[0], args[1], Math.min(7, args[2]));
      }
      return originalWrite(fd, ...args);
    };
    syncBuiltinESMExports();
    const { createProductionStandaloneFailStop, callProductionStandaloneProvider, failStopProductionStandalone } = await import(${JSON.stringify(moduleUrl)});
    const boundary = createProductionStandaloneFailStop({ directory });
    const operationId = 'r1/control/' + 'a'.repeat(64);
    const make = () => {
      if (kind === 'admission' && shape === 'primitive') return true;
      if (kind === 'secret' && shape === 'primitive') return undefined;
      if (shape === 'primitive') return (kind === 'account' ? 'Firebase ' : 'Bearer ') + 'SYNTHETIC_VALID_TOKEN';
      if (shape === 'exact-bound' || shape === 'next-bound') return (kind === 'account' ? 'Firebase ' : 'Bearer ') + 't'.repeat(shape === 'exact-bound' ? 8192 : 8193);
      if (shape === 'wrong-scheme') return 'Firebase SYNTHETIC_VALID_TOKEN';
      if (shape === 'empty') return '';
      if (shape === 'false') return false;
      if (shape === 'null') return null;
      if (shape === 'zero') return 0;
      if (shape === 'undefined') return undefined;
      if (shape === 'boxed') { const value = new String('Bearer SYNTHETIC_VALID_TOKEN'); value.toString = () => { getters++; throw new Error(secret); }; return value; }
      if (shape === 'throw') {
        const error = new Error(secret);
        Object.defineProperty(error, 'stack', { get() { getters++; return secret; } });
        Object.defineProperty(error, 'cause', { get() { getters++; return secret; } });
        throw error;
      }
      if (shape === 'thenable') return { get then() { getters++; throw new Error(secret); } };
      if (shape === 'proxy') return new Proxy({}, { get() { getters++; throw new Error(secret); }, getPrototypeOf() { getters++; throw new Error(secret); } });
      if (shape === 'hidden-reject') { Promise.reject(new Error(secret)); return {}; }
      const Native = Promise;
      let value;
      if (shape.startsWith('subclass')) {
        class Sub extends Native { constructor(...args) { super(...args); constructors++; } }
        if (shape === 'subclass-species') Object.defineProperty(Sub, Symbol.species, { get() { getters++; return Native; } });
        value = Sub.reject(new Error(secret));
        if (shape === 'subclass-nonextensible') Object.preventExtensions(value);
      } else value = Native.reject(new Error(secret));
      constructors = 0;
      if (shape === 'own-then') Object.defineProperty(value, 'then', { get() { getters++; throw new Error(secret); } });
      if (shape === 'constructor-accessor') Object.defineProperty(value, 'constructor', { get() { getters++; throw new Error(secret); } });
      if (shape === 'constructor-species') Object.defineProperty(value, 'constructor', { value: { get [Symbol.species]() { getters++; return Native; } } });
      if (shape === 'frozen') Object.freeze(value);
      return value;
    };
    await withProjectLocks({ projects: ['example-query'], lockDir: root + '/locks', legacyLockPath: root + '/legacy.lock', taskId: 'STORAGE-OBJECT', packetId: 'local-fail-stop', sourceCommit: 'a'.repeat(40), pid: process.pid, acquiredAt: '2026-09-29T00:00:00Z' }, async lease => {
      lease.markStarted();
      fs.writeFileSync(root + '/started-attempt.json', '{}', { mode: 0o600 });
      if (fault === 'existing') fs.writeFileSync(directory + '/fatal-r1.json', 'FOREIGN', { mode: 0o600 });
      if (fault === 'symlink') { fs.writeFileSync(root + '/victim', 'FOREIGN', { mode: 0o600 }); fs.symlinkSync(root + '/victim', directory + '/fatal-r1.json'); }
      if (fault === 'mode') fs.chmodSync(directory, 0o755);
      if (fault === 'replace') { fs.renameSync(directory, directory + '-old'); fs.mkdirSync(directory, { mode: 0o700 }); }
      if (fault === 'started') {
        try { const fd = fs.openSync(root + '/started-attempt.json', fs.constants.O_WRONLY); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
        catch { failStopProductionStandalone(boundary, { recording: 1, operationId, reason: 'STARTED_UNCERTAIN', providerKind: 'runtime' }); }
      }
      for (let i = 1; i <= slot; i++) {
        const provider = () => { calls++; return i === slot ? make() : 'Bearer SYNTHETIC_VALID_TOKEN'; };
        callProductionStandaloneProvider({ boundary, kind, provider, args: [], recording: 1, operationId });
      }
      if (fault === 'terminal') {
        fs.writeFileSync(root + '/terminal-attempt.json', '{}', { mode: 0o600 });
        try { const fd = fs.openSync(root + '/terminal-attempt.json', fs.constants.O_WRONLY); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
        catch { failStopProductionStandalone(boundary, { recording: 1, operationId, reason: 'TERMINAL_UNCERTAIN', providerKind: 'runtime' }); }
      }
      fs.writeFileSync(root + '/after-call', 'AFTER', { mode: 0o600 });
      lease.confirmClosed();
    });
  `;
  return spawnSync(process.execPath, ["--input-type=module"], {
    input: source,
    encoding: "utf8",
    timeout: 10000,
    env: { PATH: process.env.PATH, TMPDIR: tmpdir() },
    maxBuffer: 65536,
  });
}

function assertStopped(paths, result, { failureExpected = true, calls = 1 } = {}) {
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  assert.equal(result.status, 2);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "");
  const metrics = JSON.parse(fs.readFileSync(join(paths.root, "metrics.json")));
  assert.equal(metrics.getters, 0);
  assert.equal(metrics.constructors, 0);
  assert.equal(metrics.unhandled, 0);
  assert.equal(metrics.calls, calls);
  assert.equal(fs.existsSync(join(paths.root, "after-call")), false);
  assert.equal(fs.existsSync(join(paths.root, "started-attempt.json")), true);
  assert.equal(
    JSON.parse(fs.readFileSync(join(paths.root, "locks/example-query.lock"))).taskId,
    "STORAGE-OBJECT",
  );
  if (failureExpected) {
    const path = join(paths.capture, "fatal-r1.json");
    const bytes = fs.readFileSync(path);
    const value = JSON.parse(bytes);
    assert.equal(fs.statSync(path).mode & 0o777, 0o600);
    assert.deepEqual(Object.keys(value).toSorted(), [
      "operationIdSha256",
      "providerKind",
      "reason",
      "recording",
      "state",
      "type",
    ]);
    assert.equal(value.type, "production-fixed-failure");
    assert.equal(value.state, "NEEDS_RECOVERY");
    assert.match(value.operationIdSha256, /^[a-f0-9]{64}$/);
    assert.equal(bytes.length <= 1024, true);
    for (const copy of [
      secret,
      encodeURIComponent(secret),
      Buffer.from(secret).toString("base64"),
      Buffer.from(secret).toString("base64url"),
    ])
      assert.equal(bytes.includes(Buffer.from(copy)), false);
  }
  return metrics;
}

test("only the four declared primitive provider results return to the owned caller", () => {
  for (const kind of ["owner", "account", "admission", "secret"])
    fixture((paths) => {
      const result = child(paths, { kind });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, "");
      assert.equal(result.stderr, "");
      assert.equal(fs.existsSync(join(paths.root, "after-call")), true);
      assert.equal(fs.existsSync(join(paths.capture, "fatal-r1.json")), false);
      assert.equal(fs.existsSync(join(paths.root, "locks/example-query.lock")), false);
    });
});

test("actual rejected Promises, constructors, thenables, proxies and thrown causes stop before another turn", () => {
  for (const shape of [
    "native",
    "own-then",
    "constructor-accessor",
    "constructor-species",
    "frozen",
    "subclass",
    "subclass-species",
    "subclass-nonextensible",
    "thenable",
    "proxy",
    "hidden-reject",
    "throw",
  ])
    for (const slot of [1, 2])
      fixture((paths) => {
        const result = child(paths, { shape, slot });
        const metrics = assertStopped(paths, result, { calls: slot });
        assert.equal(metrics.fileSyncs, 1);
        assert.equal(metrics.directorySyncs, 1);
        const value = JSON.parse(fs.readFileSync(join(paths.capture, "fatal-r1.json")));
        assert.equal(value.reason, shape === "throw" ? "PROVIDER_THREW" : "PROVIDER_RESULT_UNSAFE");
      });
});

test("wrong primitive credentials never coerce while the exact token bound remains accepted", () => {
  for (const shape of [
    "next-bound",
    "wrong-scheme",
    "empty",
    "false",
    "null",
    "zero",
    "undefined",
    "boxed",
  ])
    fixture((paths) => assertStopped(paths, child(paths, { shape })));
  for (const kind of ["owner", "account"])
    fixture((paths) => {
      const result = child(paths, { shape: "exact-bound", kind });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, "");
      assert.equal(result.stderr, "");
      assert.equal(fs.existsSync(join(paths.root, "after-call")), true);
    });
  for (const kind of ["admission", "secret"])
    fixture((paths) => assertStopped(paths, child(paths, { kind, shape: "false" })));
});

test("write and both fsync failures remain silent and retain the started lease", () => {
  for (const fault of ["write", "zero-write", "file-fsync", "directory-fsync"])
    fixture((paths) =>
      assertStopped(paths, child(paths, { shape: "constructor-accessor", fault }), {
        failureExpected: false,
      }),
    );
});

test("partial writes complete the same fixed file while hardlink and inode changes stop durability", () => {
  fixture((paths) => {
    const metrics = assertStopped(
      paths,
      child(paths, { shape: "thenable", fault: "partial-write" }),
    );
    assert.equal(metrics.fileSyncs, 1);
    assert.equal(metrics.directorySyncs, 1);
  });
  for (const fault of ["hardlink", "replace-file"])
    fixture((paths) => {
      const metrics = assertStopped(paths, child(paths, { shape: "thenable", fault }), {
        failureExpected: false,
      });
      assert.equal(metrics.directorySyncs, 0);
      if (fault === "replace-file")
        assert.equal(fs.readFileSync(join(paths.capture, "fatal-r1.json"), "utf8"), "FOREIGN");
    });
});

test("exclusive file creation and original directory identity do not alter a foreign target", () => {
  for (const fault of ["existing", "symlink", "mode", "replace"])
    fixture((paths) => {
      assertStopped(paths, child(paths, { shape: "thenable", fault }), { failureExpected: false });
      if (fault === "existing")
        assert.equal(fs.readFileSync(join(paths.capture, "fatal-r1.json"), "utf8"), "FOREIGN");
      if (fault === "symlink")
        assert.equal(fs.readFileSync(join(paths.root, "victim"), "utf8"), "FOREIGN");
      if (["mode", "replace"].includes(fault))
        assert.equal(fs.existsSync(join(paths.capture, "fatal-r1.json")), false);
    });
});

test("uncertain started and terminal persistence never become normal closure", () => {
  for (const fault of ["started", "terminal"])
    fixture((paths) => {
      assertStopped(paths, child(paths, { fault }), { calls: fault === "started" ? 0 : 1 });
      assert.equal(
        JSON.parse(fs.readFileSync(join(paths.capture, "fatal-r1.json"))).reason,
        fault === "started" ? "STARTED_UNCERTAIN" : "TERMINAL_UNCERTAIN",
      );
    });
});

test("copied boundary capabilities and invalid configuration cannot invoke provider hooks", () =>
  fixture(({ capture }) => {
    const boundary = api.createProductionStandaloneFailStop({ directory: capture });
    let hooks = 0;
    const provider = () => {
      hooks++;
      return "Bearer SYNTHETIC_VALID_TOKEN";
    };
    assert.throws(
      () =>
        api.callProductionStandaloneProvider({
          boundary: { ...boundary },
          kind: "owner",
          provider,
          args: [],
          recording: 1,
          operationId: `r1/control/${"a".repeat(64)}`,
        }),
      /invalid production standalone/,
    );
    const config = {};
    Object.defineProperty(config, "directory", {
      enumerable: true,
      get() {
        hooks++;
        return capture;
      },
    });
    assert.throws(
      () => api.createProductionStandaloneFailStop(config),
      /invalid production standalone/,
    );
    assert.equal(hooks, 0);
  }));
