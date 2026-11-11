// Run by the mutation harness with every mutant (FIREEMU_MUTATION_HARNESS=1): the environment the suites run in
// has no credential and no real private root, so no mutant can reach production by falling back to a real client.
// Outside the harness (a developer's own run) this file does nothing.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import tls from "node:tls";

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
  "the harness environment: the network is closed to everything but this machine, for every client",
  { skip: !inHarness },
  async () => {
    // The harness preloads a block into every node process (NODE_OPTIONS=--import), at the socket and DNS level, so
    // a client that bypasses the send guard (the native fetch, a custom https agent, tls, net) cannot reach a real
    // host. The native clients are used on purpose.
    assert.match(process.env.NODE_OPTIONS ?? "", /--import .*net-block\.mjs/u);
    const blocked = (error) =>
      error.code === "ERR_NET_BLOCKED" || error.cause?.code === "ERR_NET_BLOCKED";
    await assert.rejects(globalThis.fetch("https://identitytoolkit.googleapis.com/"), blocked);
    await assert.rejects(globalThis.fetch("http://192.0.2.1/"), blocked);
    for (const [module, host] of [
      [https, "oauth2.googleapis.com"],
      [http, "run.googleapis.com"],
      [https, "192.0.2.1"],
    ]) {
      await assert.rejects(
        new Promise((resolve, reject) =>
          module
            .get({ hostname: host, agent: new module.Agent({ keepAlive: true }) }, resolve)
            .on("error", reject),
        ),
        blocked,
        `${host} through a custom agent`,
      );
    }
    await assert.rejects(
      new Promise((resolve, reject) =>
        net.connect({ host: "192.0.2.1", port: 443 }, resolve).on("error", reject),
      ),
      blocked,
    );
    await assert.rejects(
      new Promise((resolve, reject) =>
        tls
          .connect({ host: "cloudfunctions.googleapis.com", port: 443 }, resolve)
          .on("error", reject),
      ),
      blocked,
    );
    await assert.rejects(dns.promises.lookup("identitytoolkit.googleapis.com"), blocked);
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

test(
  "the harness environment: a child process of the test runner is blocked too",
  { skip: !inHarness },
  () => {
    const out = execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        "const r = await fetch('https://run.googleapis.com/').then(() => 'reached', (e) => e.cause?.code ?? e.code); console.log(r)",
      ],
      { encoding: "utf8", timeout: 30_000 },
    );
    assert.equal(out.trim(), "ERR_NET_BLOCKED");
  },
);
