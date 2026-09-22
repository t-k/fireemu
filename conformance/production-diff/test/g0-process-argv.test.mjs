import assert from "node:assert/strict";
import { once } from "node:events";
import { spawn } from "node:child_process";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { mock, test } from "node:test";
import * as g0 from "../g0.mjs";

const linuxBytes = (args) => Buffer.from(args.join("\0") + "\0", "utf8");

test("Linux argv decoding preserves empty arguments and BOM", () => {
  const args = ["/bin/fireemu", "", "\ufeffalias", ""];
  assert.deepEqual(g0.decodeProcessArgv(linuxBytes(args), "linux"), args);
});

test("Linux argv decoding refuses invalid UTF-8", () => {
  assert.throws(() => g0.decodeProcessArgv(Buffer.from([0x66, 0x80, 0]), "linux"));
});

test("Darwin argv decoding separates executable path from argv zero", () => {
  const args = ["launcher-alias", "", "exec"];
  const executable = Buffer.from("/tmp/fireemu\0", "utf8");
  const prefix = Buffer.alloc(4);
  prefix.writeInt32LE(args.length);
  const padding = Buffer.alloc((8 - executable.length % 8) % 8);
  const raw = Buffer.concat([prefix, executable, padding, linuxBytes(args)]);
  assert.deepEqual(g0.decodeProcessArgv(raw, "darwin"), args);
});

test("Darwin argv decoding rejects an unbounded argument buffer", () => {
  assert.throws(() => g0.decodeProcessArgv(Buffer.alloc(128 * 1024 + 1), "darwin"));
});

test("Linux process observation preserves an actual empty argument", async () => {
  const child = spawn(process.execPath, ["-e", "setTimeout(() => {}, 1000)", "", "tail"], {
    stdio: "ignore",
  });
  try {
    assert.deepEqual(g0.readOwnedProcessArgv(child.pid), [process.execPath, "-e", "setTimeout(() => {}, 1000)", "", "tail"]);
  } finally {
    child.kill("SIGKILL");
    await once(child, "close");
  }
});

test("Darwin helper uses bounded timeout and no shell or stderr exposure", () => {
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value: "darwin" });
  let options;
  const replacement = mock.method(childProcess, "execFileSync", (_command, args, received) => {
    options = received;
    assert.equal(args[0], "-I");
    throw new Error("bounded helper failure");
  });
  syncBuiltinESMExports();
  try {
    assert.equal(g0.readOwnedProcessArgv(123), null);
    assert.equal(options.timeout, 5000);
    assert.equal(options.killSignal, "SIGKILL");
    assert.equal(options.maxBuffer, 128 * 1024);
    assert.deepEqual(options.stdio, ["ignore", "pipe", "ignore"]);
    assert.equal(options.shell, undefined);
  } finally {
    replacement.mock.restore();
    syncBuiltinESMExports();
    Object.defineProperty(process, "platform", descriptor);
  }
});
