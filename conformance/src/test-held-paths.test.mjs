// Self-tests of the held-handle helper: a helper that proves an absence must not turn an error into one.
import assert from "node:assert/strict";
import { closeSync, mkdtempSync, openSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { heldPaths } from "./test-held-paths.mjs";

const errno = (code) => Object.assign(new Error(`${code}: simulated`), { code });
const linux = (readdir, readlink) => ({ platform: "linux", readdir, readlink });
const macos = (lsof) => ({ platform: "darwin", lsof });

test("an open file is reported while it is held, and not after it is closed", () => {
  const directory = mkdtempSync(join(tmpdir(), "held-paths-"));
  try {
    const path = join(directory, "held.txt");
    writeFileSync(path, "x");
    assert.deepEqual(heldPaths(directory), []);
    const fd = openSync(path, "r");
    try {
      const held = heldPaths(directory);
      assert.equal(held.length, 1, JSON.stringify(held));
      assert.ok(held[0].includes("held.txt"), held[0]);
    } finally {
      closeSync(fd);
    }
    assert.deepEqual(heldPaths(directory), []);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("on Linux the descriptors are read from /proc and only the matching paths are returned", () => {
  const links = { 3: "/work/run/held.json", 4: "/elsewhere/other.json", 5: "socket:[123]" };
  const held = heldPaths(
    "/work/run",
    linux(
      (directory) => {
        assert.equal(directory, "/proc/self/fd");
        return ["3", "4", "5"];
      },
      (path) => {
        assert.match(path, /^\/proc\/self\/fd\/[345]$/);
        return links[path.split("/").pop()];
      },
    ),
  );
  assert.deepEqual(held, ["/work/run/held.json"]);
});

test("a descriptor closed between the listing and the read is ignored", () => {
  const held = heldPaths(
    "/work/run",
    linux(
      () => ["3", "4"],
      (path) => {
        if (path.endsWith("/3")) throw errno("ENOENT");
        return "/work/run/still-held.json";
      },
    ),
  );
  assert.deepEqual(held, ["/work/run/still-held.json"]);
});

test("any other error while reading a descriptor is thrown, never turned into an empty result", () => {
  for (const code of ["EACCES", "EIO", "EPERM", "ELOOP"]) {
    assert.throws(
      () =>
        heldPaths(
          "/work/run",
          linux(
            () => ["3"],
            () => {
              throw errno(code);
            },
          ),
        ),
      (error) => error.code === code,
      code,
    );
  }
});

test("an error that is not a system error is thrown too", () => {
  assert.throws(
    () =>
      heldPaths(
        "/work/run",
        linux(
          () => ["3"],
          () => {
            throw new TypeError("boom");
          },
        ),
      ),
    TypeError,
  );
});

test("a failing listing of the descriptors is thrown", () => {
  assert.throws(
    () =>
      heldPaths(
        "/work/run",
        linux(
          () => {
            throw errno("EACCES");
          },
          () => "",
        ),
      ),
    (error) => error.code === "EACCES",
  );
});

test("the fragment may sit anywhere in the path", () => {
  const held = heldPaths(
    "/run/held",
    linux(
      () => ["3"],
      () => "/work/run/held.json",
    ),
  );
  assert.deepEqual(held, ["/work/run/held.json"]);
});

test("on macOS lsof is asked for the names of this process's files and only name lines match", () => {
  const calls = [];
  const lsof = (command, args, options) => {
    calls.push({ command, args, options });
    return [
      "p4242",
      "fcwd",
      "n/work/run",
      "f3",
      "n/work/run/held.json",
      "f4",
      "n/elsewhere/other.json",
      "f/work/run/in-a-field-that-is-not-a-name",
      "",
    ].join("\n");
  };
  const held = heldPaths("/work/run", macos(lsof));
  assert.deepEqual(held, ["n/work/run", "n/work/run/held.json"]);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "lsof");
  assert.deepEqual(calls[0].args, ["-p", String(process.pid), "-Fn"]);
  assert.equal(calls[0].options.encoding, "utf8");
});

test("an error of lsof is thrown", () => {
  const lsof = () => {
    throw errno("ENOENT");
  };
  assert.throws(
    () => heldPaths("/work/run", macos(lsof)),
    (error) => error.code === "ENOENT",
  );
});
