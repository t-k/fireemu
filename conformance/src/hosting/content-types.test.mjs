// The Content-Type table of the Hosting emulator is generated from the pinned oracle's lookup. These
// tests keep the committed table current and compare a sample with the real superstatic server.
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const hosting = fileURLToPath(new URL("../../../crates/fireemu/src/hosting/", import.meta.url));
const officialRequire = createRequire(
  createRequire(import.meta.url).resolve("firebase-tools/package.json"),
);

test("the committed content type table and samples are what the generator writes", () => {
  execFileSync(process.execPath, [join(hosting, "generate-content-types.mjs"), "--check"], {
    stdio: "pipe",
  });
});

test("the table was generated from the 15.28.2 oracle stack", () => {
  const { versions } = JSON.parse(readFileSync(join(hosting, "content-type-samples.json"), "utf8"));
  assert.equal(versions["firebase-tools"], "15.28.2");
  assert.equal(versions.superstatic, officialRequire("superstatic/package.json").version);
});

test("sampled files get the committed content type from the real superstatic server", async () => {
  const { samples } = JSON.parse(readFileSync(join(hosting, "content-type-samples.json"), "utf8"));
  const served = samples.filter(
    (row) =>
      row.file !== "" &&
      !row.file.startsWith("/") &&
      !row.file.endsWith("/") &&
      !row.file.split("/").includes("..") &&
      !row.file.split("/").includes(".") &&
      /^[\x21-\x7e]+$/.test(row.file) &&
      !/[?#%]/.test(row.file),
  );
  assert.ok(served.length > 250, "most of the sample can be served");
  const cwd = await mkdtemp(join(tmpdir(), "content-types-"));
  try {
    for (const row of served) {
      const target = join(cwd, "public", row.file);
      await mkdir(dirname(target), { recursive: true }).catch(() => {});
      await writeFile(target, "x\n").catch(() => {});
    }
    const { server } = officialRequire("superstatic");
    const listener = await new Promise((yes, no) => {
      const instance = server({
        port: 0,
        config: { public: "public" },
        cwd,
        hostname: "127.0.0.1",
        stack: "strict",
        compression: true,
      }).listen(() => yes(instance));
      instance.once("error", no);
    });
    try {
      const port = listener.address().port;
      let compared = 0;
      for (const row of served) {
        const reply = await new Promise((yes, no) =>
          http
            .get({ host: "127.0.0.1", port, path: `/${row.file}` }, (res) => {
              res.resume();
              res.on("end", () => yes(res));
            })
            .on("error", no),
        );
        if (reply.statusCode !== 200) continue; // a name the file system or the router refuses
        compared++;
        assert.equal(
          reply.headers["content-type"],
          row.contentType === null ? "false" : row.contentType,
          row.file,
        );
        assert.equal(
          reply.headers.vary === "Accept-Encoding",
          row.compressible,
          `${row.file} vary ${reply.headers.vary}`,
        );
      }
      assert.ok(compared > 200, `compared ${compared}`);
    } finally {
      listener.closeAllConnections?.();
      await new Promise((yes) => listener.close(yes));
    }
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
