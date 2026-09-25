// Saved-reference inputs must be bounded, regular and stable while being read.
// These tests use real files. Deterministic race hooks surround real FileHandle
// operations; the FIFO controls use an isolated Node process with a watchdog.
import test from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { readSource, publish } from "../io.mjs";
import { sha256 } from "../core.mjs";

const MODULE_URL = new URL("../io.mjs", import.meta.url).href;
const CHUNK = 64 * 1024;

async function fixture(t, bytes = Buffer.from("original\n")) {
  const root = await fs.mkdtemp(join(tmpdir(), "fireemu-source-read-"));
  const target = join(root, "saved.json");
  await fs.writeFile(target, bytes);
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return { root, target, bytes };
}

// Instrument only this file and retain the real OS descriptor/read operations.
function watchHandle(t, target, hooks = {}) {
  const realOpen = fs.open.bind(fs);
  const state = { opens: 0, reads: [], received: 0, readFiles: 0, closes: 0, handle: null };
  const previousOpen = fs.open;
  fs.open = async (path, flags, ...rest) => {
    const canonicalTarget = await fs.realpath(target);
    const canonicalPath = await fs.realpath(path);
    if (canonicalPath !== canonicalTarget) return realOpen(path, flags, ...rest);
    state.opens++;
    await hooks.beforeOpen?.();
    const handle = await realOpen(path, flags, ...rest);
    state.handle = handle;
    const stat = handle.stat.bind(handle);
    const read = handle.read.bind(handle);
    const readFile = handle.readFile.bind(handle);
    const close = handle.close.bind(handle);
    let statCalls = 0, readCalls = 0;
    const wrappedStat = async (...args) => {
      const value = await stat(...args);
      if (++statCalls === 1) await hooks.afterFirstStat?.();
      return value;
    };
    const wrappedRead = async (buffer, offset, length, position) => {
      const requested = hooks.shortReads ? Math.min(length, hooks.shortReads) : length;
      if (hooks.readError) throw Object.assign(new Error("injected-read"), { code: "EIO" });
      const result = hooks.earlyEof
        ? { bytesRead: 0, buffer }
        : await read(buffer, offset, requested, position);
      state.reads.push({ requested: length, received: result.bytesRead, position });
      state.received += result.bytesRead;
      if (++readCalls === 1) await hooks.afterFirstRead?.();
      return result;
    };
    const wrappedReadFile = async (...args) => {
      state.readFiles++;
      if (hooks.readError) throw Object.assign(new Error("injected-read"), { code: "EIO" });
      const value = hooks.earlyEof ? Buffer.alloc(0) : await readFile(...args);
      state.received += value.length;
      await hooks.afterFirstRead?.();
      return value;
    };
    const wrappedClose = async () => { state.closes++; return close(); };
    const wrapped = {
      fd: handle.fd,
      stat: wrappedStat,
      read: wrappedRead,
      readFile: wrappedReadFile,
      close: wrappedClose,
    };
    await hooks.afterOpen?.(wrapped);
    return wrapped;
  };
  t.after(() => { fs.open = previousOpen; });
  return state;
}

for (const size of [0, 1, 31, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK + 17]) {
  test(`regular file of ${size} bytes round-trips at the exact cap`, async (t) => {
    const bytes = Buffer.alloc(size);
    for (let i = 0; i < size; i++) bytes[i] = i % 251;
    const { root } = await fixture(t, bytes);
    assert.deepEqual(await readSource(root, "saved.json", size), bytes);
  });
}

test("default 16 MiB cap accepts equality", async (t) => {
  const bytes = Buffer.alloc(16 * 1024 * 1024, 37);
  const { root } = await fixture(t, bytes);
  assert.deepEqual(await readSource(root, "saved.json"), bytes);
});

test("default cap refuses one extra byte before open", async (t) => {
  const { root, target } = await fixture(t, Buffer.alloc(16 * 1024 * 1024 + 1));
  const watched = watchHandle(t, target);
  await assert.rejects(readSource(root, "saved.json"), /source-size-or-type/);
  assert.equal(watched.opens, 0);
});

for (const limit of [-1, 1.5, NaN, Infinity, -Infinity, true, null, "20", 20n, Number.MAX_SAFE_INTEGER + 1]) {
  test(`invalid byte cap ${String(limit)} (${typeof limit}) is refused before open`, async (t) => {
    const { root, target } = await fixture(t);
    const watched = watchHandle(t, target);
    await assert.rejects(readSource(root, "saved.json", limit), /invalid-source-byte-limit/);
    assert.equal(watched.opens, 0);
  });
}

test("the reader never uses readFile and bounds every request", async (t) => {
  const { root, target, bytes } = await fixture(t, Buffer.alloc(2 * CHUNK + 1, 42));
  const watched = watchHandle(t, target);
  assert.deepEqual(await readSource(root, "saved.json", bytes.length), bytes);
  assert.equal(watched.readFiles, 0);
  assert.ok(watched.reads.length >= 3);
  assert.ok(watched.reads.every((r) => r.requested <= CHUNK));
  assert.ok(watched.reads.every((r) => r.position + r.requested <= bytes.length + 1));
  assert.ok(watched.received <= bytes.length + 1);
  assert.equal(watched.closes, 1);
  assert.equal(watched.handle.fd, -1);
});

test("short OS reads are assembled without truncation", async (t) => {
  const { root, target, bytes } = await fixture(t, Buffer.from("0123456789".repeat(40)));
  const watched = watchHandle(t, target, { shortReads: 7 });
  assert.deepEqual(await readSource(root, "saved.json"), bytes);
  assert.ok(watched.reads.length > 50);
  assert.equal(watched.closes, 1);
});

test("growth beyond the cap is refused after at most old-size plus one byte", async (t) => {
  const { root, target, bytes } = await fixture(t, Buffer.alloc(16, 65));
  const watched = watchHandle(t, target, {
    afterFirstStat: () => fs.appendFile(target, Buffer.alloc(CHUNK * 2, 66)),
  });
  await assert.rejects(readSource(root, "saved.json", 32), /source-(changed|too-large)/);
  assert.ok(watched.received <= bytes.length + 1, `consumed ${watched.received} bytes`);
  assert.equal(watched.closes, 1);
  assert.equal(watched.handle.fd, -1);
});

test("growth below the cap is still a changed source, not a larger accepted snapshot", async (t) => {
  const { root, target } = await fixture(t);
  const watched = watchHandle(t, target, { afterFirstStat: () => fs.appendFile(target, "added") });
  await assert.rejects(readSource(root, "saved.json", 4096), /source-changed/);
  assert.equal(watched.closes, 1);
});

test("growth from an empty file is detected", async (t) => {
  const { root, target } = await fixture(t, Buffer.alloc(0));
  const watched = watchHandle(t, target, { afterFirstStat: () => fs.appendFile(target, "x") });
  await assert.rejects(readSource(root, "saved.json", 0), /source-(changed|too-large)/);
  assert.ok(watched.received <= 1);
  assert.equal(watched.closes, 1);
});

test("truncation before the first read is refused", async (t) => {
  const { root, target } = await fixture(t);
  const watched = watchHandle(t, target, { afterFirstStat: () => fs.truncate(target, 3) });
  await assert.rejects(readSource(root, "saved.json"), /source-changed/);
  assert.equal(watched.closes, 1);
});

test("truncation after the first chunk is refused", async (t) => {
  const { root, target } = await fixture(t, Buffer.alloc(2 * CHUNK, 65));
  const watched = watchHandle(t, target, { afterFirstRead: () => fs.truncate(target, CHUNK) });
  await assert.rejects(readSource(root, "saved.json"), /source-changed/);
  assert.equal(watched.closes, 1);
});

test("same-size overwrite after a read is refused", async (t) => {
  const { root, target, bytes } = await fixture(t, Buffer.alloc(2 * CHUNK, 65));
  const watched = watchHandle(t, target, { afterFirstRead: async () => {
    await fs.writeFile(target, Buffer.alloc(bytes.length, 66));
    await fs.utimes(target, new Date(1_500_000_000_000), new Date(1_500_000_000_000));
  } });
  await assert.rejects(readSource(root, "saved.json"), /source-changed/);
  assert.equal(watched.closes, 1);
});

test("metadata-only change is detected conservatively", async (t) => {
  const { root, target } = await fixture(t);
  const watched = watchHandle(t, target, { afterFirstRead: () =>
    fs.utimes(target, new Date(1_400_000_000_000), new Date(1_400_000_000_000)) });
  await assert.rejects(readSource(root, "saved.json"), /source-changed/);
  assert.equal(watched.closes, 1);
});

test("regular-file replacement between lstat and open is refused", async (t) => {
  const { root, target, bytes } = await fixture(t);
  const other = join(root, "next.json");
  await fs.writeFile(other, bytes);
  const watched = watchHandle(t, target, { beforeOpen: () => fs.rename(other, target) });
  await assert.rejects(readSource(root, "saved.json"), /source-changed/);
  assert.equal(watched.closes, 1);
});

test("regular-file replacement after a read is refused even with identical bytes", async (t) => {
  const { root, target, bytes } = await fixture(t);
  const other = join(root, "next.json");
  await fs.writeFile(other, bytes);
  const watched = watchHandle(t, target, { afterFirstRead: () => fs.rename(other, target) });
  await assert.rejects(readSource(root, "saved.json"), /source-changed/);
  assert.equal(watched.closes, 1);
});

test("unlinked input cannot be published as a still-present source", async (t) => {
  const { root, target } = await fixture(t);
  const watched = watchHandle(t, target, { afterFirstRead: () => fs.unlink(target) });
  await assert.rejects(readSource(root, "saved.json"));
  assert.equal(watched.closes, 1);
});

test("early EOF is not a successful shorter read", async (t) => {
  const { root, target } = await fixture(t);
  const watched = watchHandle(t, target, { earlyEof: true });
  await assert.rejects(readSource(root, "saved.json"), /source-changed/);
  assert.equal(watched.closes, 1);
});

test("I/O failure rejects and closes the owned descriptor", async (t) => {
  const { root, target } = await fixture(t);
  const watched = watchHandle(t, target, { readError: true });
  await assert.rejects(readSource(root, "saved.json"), { code: "EIO" });
  assert.equal(watched.closes, 1);
  assert.equal(watched.handle.fd, -1);
});

for (const path of ["../saved.json", "/saved.json", "a/../saved.json", "a//b", "./saved.json", "", "a\\b"]) {
  test(`unsafe path ${JSON.stringify(path)} stays refused`, async (t) => {
    const { root } = await fixture(t);
    await assert.rejects(readSource(root, path), /unsafe-source-path/);
  });
}

for (const mode of ["leaf", "directory"]) {
  test(`static ${mode} symlink stays refused`, async (t) => {
    const { root, target } = await fixture(t);
    if (mode === "leaf") await fs.symlink(target, join(root, "alias.json"));
    else await fs.symlink(root, join(root, "alias"));
    await assert.rejects(readSource(root, mode === "leaf" ? "alias.json" : "alias/saved.json"), /source-symlink/);
  });
}

test("directory input is refused before opening", async (t) => {
  const { root } = await fixture(t);
  const target = join(root, "folder.json");
  await fs.mkdir(target);
  const watched = watchHandle(t, target);
  await assert.rejects(readSource(root, "folder.json"), /source-size-or-type/);
  assert.equal(watched.opens, 0);
});

test("spaces and multibyte names preserve exact binary bytes", async (t) => {
  const { root } = await fixture(t);
  const directory = join(root, "保存 資料");
  await fs.mkdir(directory);
  const content = Buffer.from("{\"name\":\"日本語・🙂\",\"x\":null}\r\n\u0000", "utf8");
  await fs.writeFile(join(directory, "原文.json"), content);
  assert.deepEqual(await readSource(root, "保存 資料/原文.json", content.length), content);
});

test("existing atomic publication still round-trips without changing the digest", async (t) => {
  const { root } = await fixture(t);
  const body = Buffer.from('{"status":400,"code":"INVALID_ARGUMENT"}\n');
  await publish(join(root, "observation.json"), body);
  const read = await readSource(root, "observation.json");
  assert.deepEqual(read, body);
  assert.equal(sha256(read), sha256(body));
});

async function fifoProbe(root, race) {
  const source = `
    import { promises as fs } from 'node:fs';
    import { execFileSync } from 'node:child_process';
    import { readSource } from ${JSON.stringify(MODULE_URL)};
    const root = ${JSON.stringify(root)};
    const target = await fs.realpath(root + '/saved.json');
    if (${JSON.stringify(race)}) {
      const open = fs.open.bind(fs);
      fs.open = async (path, ...args) => {
        if (path === target) {
          await fs.unlink(path);
          execFileSync('mkfifo', [path]);
        }
        return open(path, ...args);
      };
    }
    console.log('READY');
    try { await readSource(root, 'saved.json'); console.log('UNEXPECTED-ACCEPT'); }
    catch (error) { console.log(JSON.stringify({refused:error.message})); }
  `;
  return await new Promise((resolveResult, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", source], {
      stdio: ["ignore", "pipe", "pipe"], env: { PATH: process.env.PATH },
    });
    let output = "", errors = "", timedOut = false, timer;
    const started = Date.now();
    const startup = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, 5000);
    child.stdout.on("data", (data) => {
      output += data;
      if (output.includes("READY") && !timer) {
        clearTimeout(startup);
        timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, 750);
      }
    });
    child.stderr.on("data", (data) => { errors += data; });
    child.on("error", (error) => { clearTimeout(timer); clearTimeout(startup); reject(error); });
    child.on("close", (code, signal) => {
      clearTimeout(timer); clearTimeout(startup);
      resolveResult({ code, signal, timedOut, output, errors, elapsedMs: Date.now() - started });
    });
  });
}

for (const race of [false, true]) {
  test(`FIFO ${race ? "substituted after lstat" : "present at entry"} cannot hang the reader`, async (t) => {
    const { root, target } = await fixture(t);
    if (!race) { await fs.unlink(target); execFileSync("mkfifo", [target]); }
    const observed = await fifoProbe(root, race);
    assert.equal(observed.timedOut, false, JSON.stringify(observed));
    assert.equal(observed.code, 0, JSON.stringify(observed));
    assert.match(observed.output, /"refused":"source-size-or-type"/);
    assert.equal(observed.errors, "");
  });
}
