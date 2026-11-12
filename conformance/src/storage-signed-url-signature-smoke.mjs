// Local-only smoke test of `storage.signedUrlKeys`: signed URLs made by the Admin SDK
// (`@google-cloud/storage`) with a key generated here are verified by fireemu under the strict
// profile. The key is synthetic, written to a private temporary directory and removed at the end.
//
//   node conformance/src/storage-signed-url-signature-smoke.mjs <path to the fireemu binary>
//
// The outer run generates the key and the configuration and starts `fireemu exec`; the inner run
// (the same file, with `--inner`) is the command `fireemu exec` runs.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { cert, deleteApp, initializeApp } from "firebase-admin/app";
import { getStorage } from "firebase-admin/storage";

const PROJECT = "demo-signed-url";
const CLIENT_EMAIL = `fixture@${PROJECT}.iam.gserviceaccount.com`;

function outer(binary) {
  const dir = mkdtempSync(join(tmpdir(), "fireemu-signed-url-"));
  try {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    writeFileSync(join(dir, "public.pem"), publicKey.export({ type: "spki", format: "pem" }));
    writeFileSync(join(dir, "private.pem"), privateKey.export({ type: "pkcs8", format: "pem" }), {
      mode: 0o600,
    });
    const config = {
      schemaVersion: 1,
      profile: "strict",
      daemon: { clockStart: "2026-08-29T12:01:00Z" },
      storage: { signedUrlKeys: [join(dir, "public.pem")] },
    };
    writeFileSync(join(dir, "fireemu.json"), JSON.stringify(config));
    const run = spawnSync(
      binary,
      [
        "exec",
        "--config",
        join(dir, "fireemu.json"),
        "--only",
        "storage",
        "--project",
        PROJECT,
        "--",
        process.execPath,
        fileURLToPath(import.meta.url),
        "--inner",
        join(dir, "private.pem"),
      ],
      { stdio: "inherit", env: { ...process.env, HOME: dir } },
    );
    process.exitCode = run.status ?? 1;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function inner(privateKeyFile) {
  const { readFileSync } = await import("node:fs");
  assert.ok(process.env.FIREBASE_STORAGE_EMULATOR_HOST || process.env.STORAGE_EMULATOR_HOST);
  const app = initializeApp({
    credential: cert({
      projectId: PROJECT,
      clientEmail: CLIENT_EMAIL,
      privateKey: readFileSync(privateKeyFile, "utf8"),
    }),
    storageBucket: `${PROJECT}.appspot.com`,
  });
  try {
    const bucket = getStorage(app).bucket();
    const file = bucket.file("signed/a # image (1).png");
    const options = {
      version: "v4",
      action: "write",
      expires: Date.now() + 5 * 60 * 1000,
      contentType: "image/png",
      extensionHeaders: { "x-goog-content-length-range": "0,16" },
    };
    const [url] = await file.getSignedUrl(options);
    const headers = {
      "Content-Type": "image/png",
      "x-goog-content-length-range": "0,16",
    };
    const bytes = Uint8Array.from([137, 80, 78, 71]);
    const good = await fetch(url, { method: "PUT", headers, body: bytes });
    assert.equal(good.status, 200, await good.text());
    assert.deepEqual((await file.download())[0], Buffer.from(bytes));

    const cases = {
      "another content type": () =>
        fetch(url, {
          method: "PUT",
          headers: { ...headers, "Content-Type": "text/plain" },
          body: bytes,
        }),
      "another range": () =>
        fetch(url, {
          method: "PUT",
          headers: { ...headers, "x-goog-content-length-range": "0,3" },
          body: bytes,
        }),
      "another object": async () => {
        const other = new URL(url);
        other.pathname = other.pathname.replace("image%20%281%29", "image%20%282%29");
        assert.notEqual(other.pathname, new URL(url).pathname);
        return fetch(other, { method: "PUT", headers, body: bytes });
      },
      "tampered signature": async () => {
        const tampered = new URL(url);
        const signature = tampered.searchParams.get("X-Goog-Signature");
        tampered.searchParams.set(
          "X-Goog-Signature",
          `${signature.slice(0, -1)}${signature.endsWith("0") ? "1" : "0"}`,
        );
        return fetch(tampered, { method: "PUT", headers, body: bytes });
      },
    };
    for (const [label, send] of Object.entries(cases)) {
      const response = await send();
      const body = await response.text();
      assert.equal(response.status, 403, `${label}: ${body}`);
      assert.match(body, /<Code>SignatureDoesNotMatch<\/Code>/, label);
      assert.match(body, /<CanonicalRequest>PUT\n/, label);
    }

    const [readUrl] = await bucket.file("signed/a # image (1).png").getSignedUrl({
      version: "v4",
      action: "read",
      expires: Date.now() + 5 * 60 * 1000,
    });
    const read = await fetch(readUrl);
    assert.equal(read.status, 200);
    assert.deepEqual(Buffer.from(await read.arrayBuffer()), Buffer.from(bytes));
    const wrongMethod = await fetch(readUrl, { method: "HEAD" });
    assert.notEqual(wrongMethod.status, 200);
    console.log("storage signed URL signature smoke: ok");
  } finally {
    await deleteApp(app);
  }
}

if (process.argv[2] === "--inner") {
  await inner(process.argv[3]);
} else {
  assert.ok(process.argv[2], "usage: node storage-signed-url-signature-smoke.mjs <fireemu binary>");
  outer(process.argv[2]);
}
