import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { execFileSync } from "node:child_process";

const module = await import("./storage-object/owner-adc.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const data = {
  type: "authorized_user",
  client_id: "fixture-owner-client.apps.googleusercontent.com",
  client_secret: "FIXTURE_ONLY_CLIENT_SECRET",
  refresh_token: "FIXTURE_ONLY_REFRESH_TOKEN",
  quota_project_id: "example-project",
};
function fixture(body, action) {
  const directory = mkdtempSync(join(tmpdir(), "storage-object-adc-test-"));
  chmodSync(directory, 0o700);
  const path = join(directory, "fixture.json");
  const bytes = Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
  writeFileSync(path, bytes, { mode: 0o600 });
  const input = {
    path,
    expectedSha256: createHash("sha256").update(bytes).digest("hex"),
    expectedClientId: data.client_id,
    expectedQuotaProjectId: "example-project",
  };
  try {
    action(input, directory);
  } finally {
    rmSync(directory, { recursive: true });
  }
}
function read(input) {
  assert.equal(typeof module.readProductionOwnerAdc, "function", "owner ADC reader is missing");
  return module.readProductionOwnerAdc(input);
}

function withFsMethod(name, replacement, action) {
  const original = fs[name];
  fs[name] = (...args) => replacement(original, ...args);
  syncBuiltinESMExports();
  try {
    action();
  } finally {
    fs[name] = original;
    syncBuiltinESMExports();
  }
}

test("a pinned private ADC is read once, exposes only a receipt and keeps refresh material in memory", () => {
  fixture(data, (input, directory) => {
    const owner = read(input);
    assert.deepEqual(owner.receipt, {
      sha256: input.expectedSha256,
      type: "authorized_user",
      clientId: data.client_id,
      quotaProjectId: "example-project",
    });
    assert.equal(Object.isFrozen(owner), true);
    assert.equal(Object.isFrozen(owner.receipt), true);
    assert.equal(JSON.stringify(owner).includes(data.refresh_token), false);
    assert.equal(JSON.stringify(owner).includes(data.client_secret), false);
    writeFileSync(input.path, "changed after the single read");
    const body = new URLSearchParams(owner.exchangeBody().toString());
    assert.equal(body.get("grant_type"), "refresh_token");
    assert.equal(body.get("refresh_token"), data.refresh_token);
    assert.equal(body.get("client_secret"), data.client_secret);
    assert.deepEqual(readdirSync(directory), ["fixture.json"]);
    owner.dispose();
    owner.dispose();
    assert.throws(() => owner.exchangeBody(), /^Error: owner ADC is unavailable$/);
  });
});

test("hash, client and optional quota or universe bindings cannot change", () => {
  fixture(data, (input) => {
    for (const change of [
      { expectedSha256: "0".repeat(64) },
      { expectedClientId: "different-client" },
      { expectedQuotaProjectId: "different-project" },
    ])
      assert.throws(() => read({ ...input, ...change }), /^Error: owner ADC is unavailable$/);
  });
  for (const change of [
    { type: "service_account" },
    { universe_domain: "different.example" },
    { refresh_token: "" },
    { client_secret: "secret\nwith newline" },
    { unexpected: "FIXTURE_ONLY_SECRET" },
  ])
    fixture({ ...data, ...change }, (input) =>
      assert.throws(() => read(input), /^Error: owner ADC is unavailable$/),
    );
  fixture({ ...data, universe_domain: "googleapis.com", account: "" }, (input) => {
    read(input).dispose();
  });
});

test("symlinks, public file modes, directories and oversized files reject before returning credentials", () => {
  fixture(data, (input, directory) => {
    const symlink = join(directory, "link.json");
    symlinkSync(input.path, symlink);
    assert.throws(() => read({ ...input, path: symlink }), /^Error: owner ADC is unavailable$/);
    chmodSync(input.path, 0o644);
    assert.throws(() => read(input), /^Error: owner ADC is unavailable$/);
    assert.throws(() => read({ ...input, path: directory }), /^Error: owner ADC is unavailable$/);
  });
  const json = JSON.stringify(data);
  fixture(json + " ".repeat(64 * 1024 + 1 - Buffer.byteLength(json)), (input) => {
    assert.throws(() => read(input), /^Error: owner ADC is unavailable$/);
  });
  fixture(json + " ".repeat(64 * 1024 - Buffer.byteLength(json)), (input) => {
    read(input).dispose();
  });
});

test("duplicate credential keys and invalid UTF8 or JSON shapes cannot replace the pinned credential", () => {
  for (const bytes of [
    JSON.stringify(data).replace('"authorized_user"', '"service_account","type":"authorized_user"'),
    "[]",
    "null",
    "{",
    "\ufeff" + JSON.stringify(data),
  ])
    fixture(bytes, (input) => {
      assert.throws(() => read(input), /^Error: owner ADC is unavailable$/);
    });
  fixture(data, (input) => {
    writeFileSync(input.path, Buffer.from([0xff, 0x7b, 0x7d]));
    input.expectedSha256 = createHash("sha256")
      .update(Buffer.from([0xff, 0x7b, 0x7d]))
      .digest("hex");
    assert.throws(() => read(input), /^Error: owner ADC is unavailable$/);
  });
});

test("unknown or accessor options reject without executing getters or leaking their text", () => {
  fixture(data, (input) => {
    assert.throws(
      () => read({ ...input, extra: "FIXTURE_ONLY_SECRET" }),
      /^Error: owner ADC is unavailable$/,
    );
    let calls = 0;
    const changed = { ...input };
    Object.defineProperty(changed, "path", {
      enumerable: true,
      get() {
        calls++;
        throw new Error("FIXTURE_ONLY_SECRET");
      },
    });
    assert.throws(() => read(changed), /^Error: owner ADC is unavailable$/);
    assert.equal(calls, 0);
  });
});

test("proxy input traps cannot choose or inspect the credential path", () => {
  fixture(data, (input) => {
    let calls = 0;
    const proxy = new Proxy(input, {
      getOwnPropertyDescriptor() {
        calls++;
        throw new Error("FIXTURE_ONLY_PROXY_SECRET");
      },
    });
    assert.throws(() => read(proxy), /^Error: owner ADC is unavailable$/);
    assert.equal(calls, 0);
  });
});

test("foreign ownership or a changed fstat snapshot reject and close the credential descriptor", () => {
  const fields = ["dev", "ino", "mode", "uid", "size", "mtimeNs", "ctimeNs"];
  fixture(data, (input) => {
    for (const field of ["foreign-owner", ...fields]) {
      let calls = 0,
        opened;
      withFsMethod(
        "fstatSync",
        (original, descriptor, options) => {
          opened = descriptor;
          const stat = original(descriptor, options);
          calls++;
          if (field === "foreign-owner" || calls === 2) {
            const key = field === "foreign-owner" ? "uid" : field;
            return Object.assign(Object.create(Object.getPrototypeOf(stat)), stat, {
              [key]: stat[key] + 1n,
            });
          }
          return stat;
        },
        () => {
          assert.throws(() => read(input), /^Error: owner ADC is unavailable$/);
        },
      );
      assert.equal(calls, field === "foreign-owner" ? 1 : 2);
      assert.throws(() => fs.fstatSync(opened), { code: "EBADF" });
    }
  });
});

test("a FIFO is opened nonblocking and rejected as a credential file", () => {
  fixture(data, (input, directory) => {
    const fifo = join(directory, "fixture.fifo");
    execFileSync("mkfifo", [fifo]);
    let observedFlags;
    withFsMethod(
      "openSync",
      (original, path, flags, mode) => {
        observedFlags = flags;
        assert.notEqual(flags & fs.constants.O_NONBLOCK, 0);
        return original(path, flags, mode);
      },
      () => {
        assert.throws(() => read({ ...input, path: fifo }), /^Error: owner ADC is unavailable$/);
      },
    );
    assert.notEqual(observedFlags & fs.constants.O_NONBLOCK, 0);
  });
});
