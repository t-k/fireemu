// Run by the mutation harness with every mutant (FIREEMU_MUTATION_HARNESS=1): the environment the suites run in
// has no credential and no real private root, so no mutant can reach production by falling back to a real client.
// Outside the harness (a developer's own run) this file does nothing.
import assert from "node:assert/strict";
import http from "node:http";
import https from "node:https";
import { existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { PRIVATE_ROOT } from "./production.mjs";
import { SEND_FLAG } from "./send-guard.mjs";

const inHarness = process.env.FIREEMU_MUTATION_HARNESS === "1";

test(
  "the harness environment: no credential variable, no send flag, an empty home",
  { skip: !inHarness },
  () => {
    assert.equal(process.env[SEND_FLAG], undefined);
    const credentialVariables = Object.keys(process.env).filter((name) =>
      /^(GOOGLE_|CLOUDSDK_|FIREBASE_TOKEN|GCLOUD_|GCP_|AWS_|GH_TOKEN|GITHUB_TOKEN|FIREEMU_OWNER_ADC|FIREEMU_.*(KEY|TOKEN|SECRET))/u.test(
        name,
      ),
    );
    assert.deepEqual(credentialVariables, []);
    assert.deepEqual(readdirSync(homedir()), [], "HOME is an empty directory");
    assert.equal(existsSync(join(homedir(), ".config/gcloud")), false);
  },
);

test(
  "the harness environment: the private root is the copy's own, empty, and the key path is absent",
  { skip: !inHarness },
  () => {
    const root = process.env.FIREEMU_MUTATION_WORK;
    assert.ok(root, "the harness names its work directory");
    assert.ok(PRIVATE_ROOT.startsWith(root), `${PRIVATE_ROOT} is inside ${root}`);
    assert.equal(existsSync(PRIVATE_ROOT), false, "there is no private directory at all");
    assert.equal(existsSync(join(PRIVATE_ROOT, "oracle-credentials")), false);
    assert.equal(existsSync(join(PRIVATE_ROOT, "runs/sandbox-ledger.jsonl")), false);
  },
);

test(
  "the harness environment: the network is closed to everything but this machine",
  { skip: !inHarness },
  async () => {
    // The harness points every outbound connection of the node process at a closed local port (NODE_USE_ENV_PROXY),
    // so even a client that bypasses the send guard cannot reach a real host. The native fetch is used on purpose.
    await assert.rejects(
      globalThis.fetch("https://identitytoolkit.googleapis.com/"),
      (error) => error.cause?.code === "ECONNREFUSED",
    );
    await assert.rejects(
      new Promise((resolve, reject) =>
        https.get("https://oauth2.googleapis.com/", resolve).on("error", reject),
      ),
      (error) => error.code === "ECONNREFUSED",
    );
    const server = http.createServer((req, res) => res.end("local"));
    await new Promise((done) => server.listen(0, "127.0.0.1", done));
    try {
      const response = await globalThis.fetch(`http://127.0.0.1:${server.address().port}/`);
      assert.equal(await response.text(), "local");
    } finally {
      server.closeAllConnections?.();
      await new Promise((done) => server.close(done));
    }
  },
);
