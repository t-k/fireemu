import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { gunzipSync } from "node:zlib";

import { SANDBOX_PROJECT } from "./auth-account/harness.mjs";
import {
  approved,
  checkWebConfig,
  hostingRecover,
  hostingSmoke,
  LIMITS,
  limitedFetch,
  runToRecover,
  sandboxBusy,
  scriptDigest,
  SOURCES,
  TASK_ID,
  uncommitted,
  withSandboxLock,
} from "./auth-federation/hosting.mjs";
import { generateSigningKey } from "./auth-federation/idp.mjs";

const RUN = "a1b2c3";
const HOST = `${SANDBOX_PROJECT}--fed-${RUN}-x7y8z9.web.app`;
const VERSION = `sites/${SANDBOX_PROJECT}/versions/v1`;
const DOMAINS = [`${SANDBOX_PROJECT}.firebaseapp.com`, `${SANDBOX_PROJECT}.web.app`];

const reply = (status, body, headers = {}) =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers });

/**
 * A fake of the Hosting, Identity Toolkit and Service Usage APIs and the channel's host.
 * `overrides[name]` replaces one answer; `served` holds what the channel serves.
 */
function fakeSandbox(overrides = {}) {
  const calls = [];
  const state = { uploads: {}, served: {}, channel: false, domains: [...DOMAINS] };
  const answer = (name, fallback) => (overrides[name] ? overrides[name](state) : fallback());
  const fetchImpl = async (url, init = {}) => {
    const method = init.method ?? "GET";
    calls.push({ method, url, body: init.body, headers: init.headers ?? {} });
    const u = new URL(url);
    if (u.host === HOST) {
      state.lastIssuerUrl = url;
      return answer("issuer", () =>
        state.channel && state.served[u.pathname]
          ? reply(200, state.served[u.pathname], { "content-type": "application/json" })
          : reply(404, "not found"),
      );
    }
    if (u.host === "serviceusage.googleapis.com") {
      return answer("usage", () => reply(200, { state: "ENABLED" }));
    }
    if (u.host === "identitytoolkit.googleapis.com") {
      return answer("config", () => reply(200, { authorizedDomains: state.domains }));
    }
    if (u.host === "upload-firebasehosting.googleapis.com") {
      state.uploads[u.pathname.split("/").at(-1)] = init.body;
      return answer("upload", () => reply(200, {}));
    }
    const path = u.pathname.replace("/v1beta1/", "");
    if (method === "GET" && path === `projects/${SANDBOX_PROJECT}/sites/${SANDBOX_PROJECT}`) {
      return answer("site", () => reply(200, { name: path }));
    }
    if (method === "GET" && path.endsWith("/channels")) {
      return answer("channels", () => reply(200, { channels: [{ name: `${path}/live` }] }));
    }
    if (method === "POST" && path.endsWith("/channels")) {
      state.channel = true;
      return answer("create", () =>
        reply(200, { name: `${path}/fed-${RUN}`, url: `https://${HOST}` }),
      );
    }
    if (method === "POST" && path.endsWith("/versions")) {
      return answer("version", () => reply(200, { name: VERSION }));
    }
    if (path.endsWith(":populateFiles")) {
      const { files } = JSON.parse(init.body);
      state.hashes = files;
      return answer("populate", () =>
        reply(200, {
          uploadUrl: `https://upload-firebasehosting.googleapis.com/upload/${VERSION}/files`,
          uploadRequiredHashes: Object.values(files),
        }),
      );
    }
    if (method === "PATCH" && path === VERSION) {
      state.finalized = JSON.parse(init.body);
      return answer("finalize", () => reply(200, {}));
    }
    if (method === "POST" && path.endsWith("/releases")) {
      // Serve what was uploaded, by path, as the release would.
      for (const [file, hash] of Object.entries(state.hashes ?? {})) {
        state.served[file] = gunzipSync(state.uploads[hash]).toString("utf8");
      }
      return answer("release", () => reply(200, {}));
    }
    if (method === "DELETE" && path.endsWith(`/channels/fed-${RUN}`)) {
      return answer("delete", () => {
        state.channel = false;
        return reply(200, {});
      });
    }
    if (method === "GET" && path.endsWith(`/channels/fed-${RUN}`)) {
      return answer("channel", () =>
        state.channel ? reply(200, { url: `https://${HOST}` }) : reply(404, {}),
      );
    }
    if (method === "GET" && path === VERSION) {
      return answer("versionGet", () => reply(200, { status: "ABANDONED" }));
    }
    return reply(500, { unexpected: `${method} ${url}` });
  };
  return { fetchImpl, calls, state };
}

async function smoke(fake, extra = {}) {
  const ledger = [];
  const { call, used } = limitedFetch(fake.fetchImpl, { run: RUN });
  const { jwk } = generateSigningKey({ kid: "fireemu-smoke" });
  const sleeps = [];
  const outcome = await hostingSmoke({
    api: call,
    run: RUN,
    jwks: [jwk],
    forbidden: ["123456789012"],
    appendLedger: async (entry) => ledger.push(entry),
    sleep: async (ms) => sleeps.push(ms),
    stop: { check() {} },
    meta: { token: "fake-token", gitSha: "abc", digest: "d".repeat(64) },
    ...extra,
  }).catch((error) => ({ thrown: error }));
  return { outcome, ledger, used, sleeps, jwk };
}

test("a smoke publishes the issuer on the run's channel, reads it back and deletes it", async () => {
  const fake = fakeSandbox();
  const { outcome, ledger, used, jwk } = await smoke(fake);
  assert.equal(outcome.outcome, "smoke-passed", JSON.stringify(outcome));
  assert.deepEqual(
    fake.calls.map(({ method, url }) => `${method} ${new URL(url).host}${new URL(url).pathname}`),
    [
      "GET serviceusage.googleapis.com/v1/projects/fireemu-oracle-idp/services/firebasehosting.googleapis.com",
      "GET firebasehosting.googleapis.com/v1beta1/projects/fireemu-oracle-idp/sites/fireemu-oracle-idp",
      "GET firebasehosting.googleapis.com/v1beta1/projects/fireemu-oracle-idp/sites/fireemu-oracle-idp/channels",
      "GET identitytoolkit.googleapis.com/admin/v2/projects/fireemu-oracle-idp/config",
      "POST firebasehosting.googleapis.com/v1beta1/projects/fireemu-oracle-idp/sites/fireemu-oracle-idp/channels",
      "POST firebasehosting.googleapis.com/v1beta1/projects/-/sites/fireemu-oracle-idp/versions",
      `POST firebasehosting.googleapis.com/v1beta1/${VERSION}:populateFiles`,
      ...Object.values(fake.state.hashes).map(
        (hash) => `POST upload-firebasehosting.googleapis.com/upload/${VERSION}/files/${hash}`,
      ),
      `PATCH firebasehosting.googleapis.com/v1beta1/${VERSION}`,
      `POST firebasehosting.googleapis.com/v1beta1/projects/-/sites/fireemu-oracle-idp/channels/fed-${RUN}/releases`,
      `GET ${HOST}/oidc/${RUN}/.well-known/openid-configuration`,
      `GET ${HOST}/oidc/${RUN}/jwks.json`,
      `DELETE firebasehosting.googleapis.com/v1beta1/projects/fireemu-oracle-idp/sites/fireemu-oracle-idp/channels/fed-${RUN}`,
      `GET firebasehosting.googleapis.com/v1beta1/projects/fireemu-oracle-idp/sites/fireemu-oracle-idp/channels/fed-${RUN}`,
      `GET firebasehosting.googleapis.com/v1beta1/${VERSION}`,
      `GET ${HOST}/oidc/${RUN}/.well-known/openid-configuration`,
      `GET ${HOST}/oidc/${RUN}/jwks.json`,
      "GET identitytoolkit.googleapis.com/admin/v2/projects/fireemu-oracle-idp/config",
    ],
  );
  // No request writes the Auth config; the channel lives a day at most.
  assert.ok(
    !fake.calls.some(({ method, url }) => method !== "GET" && url.includes("identitytoolkit")),
  );
  assert.deepEqual(JSON.parse(fake.calls[4].body), { ttl: "86400s" });
  // The uploaded files are the ones named by hash, and the issuer is the channel's.
  for (const [path, hash] of Object.entries(fake.state.hashes)) {
    assert.equal(createHash("sha256").update(fake.state.uploads[hash]).digest("hex"), hash, path);
  }
  const discovery = JSON.parse(fake.state.served[`/oidc/${RUN}/.well-known/openid-configuration`]);
  assert.equal(discovery.issuer, `https://${HOST}/oidc/${RUN}`);
  assert.deepEqual(JSON.parse(fake.state.served[`/oidc/${RUN}/jwks.json`]).keys[0].kid, jwk.kid);
  assert.deepEqual(fake.state.finalized.status, "FINALIZED");
  assert.deepEqual(
    fake.state.finalized.config.headers.map((h) => h.glob).toSorted(),
    Object.keys(fake.state.hashes).toSorted(),
  );
  // Every API request carries the owner's token and the sandbox as quota project; the
  // issuer's host gets no credential.
  for (const { url, headers } of fake.calls) {
    if (new URL(url).host === HOST) assert.equal(headers.authorization, undefined, url);
    else {
      assert.equal(headers.authorization, "Bearer fake-token", url);
      assert.equal(headers["x-goog-user-project"], SANDBOX_PROJECT, url);
    }
  }
  // The ledger has a started line and a terminal line with the read-backs.
  assert.equal(ledger[0].event, "started");
  assert.equal(ledger[0].estimatedUsd, 0);
  assert.deepEqual(ledger[0].requestLimits, LIMITS);
  assert.equal(ledger[0].scriptDigest, "d".repeat(64));
  assert.deepEqual(ledger.at(-1), outcome);
  assert.equal(outcome.channelDeleted, true);
  assert.equal(outcome.channelReadBack, "absent");
  assert.equal(outcome.authorizedDomainsUnchanged, true);
  assert.equal(outcome.issuerGone, true);
  assert.equal(outcome.versionStatus, "ABANDONED");
  assert.deepEqual(used, { api: 15, issuer: 4 });
});

test("a prechecks failure stops before the ledger's started line and sends no write", async () => {
  const cases = {
    "hosting disabled": { usage: () => reply(200, { state: "DISABLED" }) },
    "no default site": { site: () => reply(404, {}) },
    "an earlier channel": {
      channels: () => reply(200, { channels: [{ name: `x/channels/fed-d4e5f6` }] }),
    },
  };
  const expected = {
    "hosting disabled": /firebasehosting is DISABLED/,
    "no default site": /default site: HTTP 404/,
    "an earlier channel": /channels of earlier runs remain/,
  };
  for (const [name, overrides] of Object.entries(cases)) {
    const fake = fakeSandbox(overrides);
    const { outcome, ledger } = await smoke(fake);
    assert.match(String(outcome.thrown?.message), expected[name], name);
    assert.deepEqual(ledger, [], name);
    assert.ok(
      fake.calls.every(({ method }) => method === "GET"),
      name,
    );
  }
});

test("whatever fails after the channel exists, it is deleted and read back", async () => {
  const cases = {
    "populate fails": { populate: () => reply(500, {}) },
    "a foreign channel host": {
      create: (state) => {
        state.channel = true;
        return reply(200, { url: "https://evil.web.app" });
      },
    },
    "a read back that is not served as JSON": {
      // The right bytes under another type: an Identity Platform fetch may refuse them.
      issuer: (state) =>
        state.channel
          ? reply(200, state.served[new URL(state.lastIssuerUrl).pathname], {
              "content-type": "text/plain",
            })
          : reply(404, ""),
    },
    "an upload URL on another host": {
      populate: (state) =>
        reply(200, {
          uploadUrl: "https://storage.googleapis.com/upload",
          uploadRequiredHashes: Object.values(state.hashes),
        }),
    },
  };
  const expected = {
    "populate fails": /populateFiles: HTTP 500/,
    "a foreign channel host": /channel host evil.web.app is not the run's preview channel/,
    "a read back that is not served as JSON": /openid-configuration: 200 text\/plain same=true/,
    "an upload URL on another host": /upload URL storage.googleapis.com is not reviewed/,
  };
  for (const [name, overrides] of Object.entries(cases)) {
    const fake = fakeSandbox(overrides);
    const { outcome } = await smoke(fake);
    assert.equal(outcome.outcome, "failed-cleaned", `${name}: ${JSON.stringify(outcome)}`);
    assert.match(outcome.error, expected[name], name);
    assert.equal(outcome.channelDeleted, true, name);
    assert.equal(outcome.channelReadBack, "absent", name);
    assert.ok(
      fake.calls.some(({ method }) => method === "DELETE"),
      name,
    );
  }
});

test("a changed authorizedDomains, a channel left or an issuer still served needs recovery", async () => {
  // The config read after the run differs from the one before it.
  let reads = 0;
  const differing = fakeSandbox({
    config: () =>
      reply(200, { authorizedDomains: (reads += 1) === 1 ? DOMAINS : [...DOMAINS, HOST] }),
  });
  const domains = await smoke(differing);
  assert.equal(domains.outcome.authorizedDomainsUnchanged, false);
  assert.equal(domains.outcome.outcome, "needs-recovery");

  const kept = fakeSandbox({ delete: () => reply(500, {}) });
  const left = await smoke(kept);
  assert.equal(left.outcome.outcome, "needs-recovery");
  assert.equal(left.outcome.channelDeleted, false);
  assert.equal(left.outcome.channelReadBack, "present");

  const cached = fakeSandbox({
    issuer: (state) =>
      reply(200, state.served[`/oidc/${RUN}/jwks.json`] ?? "{}", {
        "content-type": "application/json",
      }),
  });
  const stale = await smoke(cached);
  assert.equal(stale.outcome.issuerGone, false);
  assert.equal(stale.outcome.outcome, "needs-recovery");
  // Five rounds a minute apart, within the issuer limit.
  assert.deepEqual(stale.sleeps, [60_000, 60_000, 60_000, 60_000]);
  assert.ok(stale.used.issuer <= LIMITS.issuer);
});

test("a stop request ends the smoke at the next step and still cleans up", async () => {
  let steps = 0;
  const fake = fakeSandbox();
  const { outcome } = await smoke(fake, {
    stop: {
      check() {
        steps += 1;
        if (steps === 2) throw new Error("stopped by SIGINT");
      },
    },
  });
  assert.equal(outcome.outcome, "failed-cleaned");
  assert.match(outcome.error, /SIGINT/);
  assert.ok(!fake.calls.some(({ url }) => url.includes(":populateFiles")));
  assert.equal(outcome.channelReadBack, "absent");
});

test("requests go only to reviewed hosts over https and within the limits", async () => {
  const ok = async () => reply(200, {});
  const { call, used } = limitedFetch(ok, { run: RUN, limits: { api: 2, issuer: 1 } });
  await assert.rejects(call("https://evil.example/x"), /not reviewed/);
  await assert.rejects(call(`https://${SANDBOX_PROJECT}--fed-d4e5f6-x.web.app/x`), /not reviewed/);
  await assert.rejects(call(`https://${SANDBOX_PROJECT}.web.app/x`), /not reviewed/);
  await assert.rejects(call("http://firebasehosting.googleapis.com/x"), /not https/);
  await call("https://firebasehosting.googleapis.com/a");
  await call("https://identitytoolkit.googleapis.com/b");
  await assert.rejects(call("https://firebasehosting.googleapis.com/c"), /api request limit 2/);
  await call(`https://${HOST}/x`);
  await assert.rejects(call(`https://${HOST}/y`), /issuer request limit 1/);
  assert.deepEqual(used, { api: 2, issuer: 1 });
});

test("the smoke starts only on a free sandbox and a digest the owner approved", async () => {
  const now = Date.parse("2026-09-27T12:00:00Z");
  const line = (task, ts, extra = {}) =>
    JSON.stringify({ ts, project: SANDBOX_PROJECT, taskId: task, ...extra });
  assert.equal(sandboxBusy("", now), undefined);
  assert.equal(
    sandboxBusy(line("FS-RULES", "2026-09-27T11:00:00Z", { outcome: "recorded" }), now),
    undefined,
  );
  assert.match(
    sandboxBusy(line("FS-RULES", "2026-09-27T11:45:00Z", { outcome: "recorded" }), now),
    /FS-RULES wrote/,
  );
  assert.match(
    sandboxBusy(line("FS-RULES", "2026-09-27T09:00:00Z", { event: "started" }), now),
    /FS-RULES at .* has not finished or recovered/,
  );
  // Another task waiting for recovery holds the sandbox however old its line is, whether the
  // lane writes it as an event or as an outcome.
  assert.match(
    sandboxBusy(line("FS-RULES-SANDBOX", "2026-09-26T02:06:35Z", { event: "needs-recovery" }), now),
    /FS-RULES-SANDBOX at .* has not finished or recovered/,
  );
  assert.match(
    sandboxBusy(line(TASK_ID, "2026-09-26T02:06:35Z", { event: "needs-recovery" }), now),
    /recover it first/,
  );
  assert.match(
    sandboxBusy(line("FS-RULES", "2026-09-26T09:00:00Z", { outcome: "needs-recovery" }), now),
    /FS-RULES at .* has not finished or recovered/,
  );
  assert.match(sandboxBusy(line("FS-RULES", "not a time"), now), /FS-RULES wrote/);
  assert.match(
    sandboxBusy(line(TASK_ID, "2026-09-27T09:00:00Z", { event: "started" }), now),
    /recover it first/,
  );
  assert.match(
    sandboxBusy(line(TASK_ID, "2026-09-27T09:00:00Z", { outcome: "needs-recovery" }), now),
    /recover it first/,
  );
  // Another project's lines do not hold this one; an unreadable line stops the run.
  assert.equal(
    sandboxBusy(
      JSON.stringify({ ts: "2026-09-27T11:59:00Z", project: "fireemu-oracle-sbx", taskId: "X" }),
      now,
    ),
    undefined,
  );
  assert.throws(() => sandboxBusy("{not json", now), /does not parse/);
});

test("only a fixed-form owner line naming the full digest approves, until it is revoked", async () => {
  const digest = await scriptDigest();
  assert.match(digest, /^[0-9a-f]{64}$/);
  const approval = `- 2026-09-27 | AUTH-FEDERATION | hosting-smoke APPROVED ${digest}（preview channel、API 15件） | オーナー（直接の返答「承認」） | review-2.md`;
  assert.ok(approved(approval, digest));
  const refused = {
    "a review record": `- 2026-09-27 | AUTH-FEDERATION | hosting-smoke ${digest} の再レビューはREQUEST_CHANGES。承認しない | Claude（委任） | x`,
    "a delegated decider": approval.replace("オーナー（直接の返答「承認」）", "Claude（委任）"),
    "a draft packet": `- 2026-09-27 | AUTH-FEDERATION | hosting-smoke-draft APPROVED ${digest} | オーナー | x`,
    "a prefixed packet": `- 2026-09-27 | AUTH-FEDERATION | xhosting-smoke APPROVED ${digest} | オーナー | x`,
    "the task name only": `AUTH-FEDERATION-SANDBOX hosting-smoke APPROVED ${digest}`,
    "12 digits only": approval.replace(digest, digest.slice(0, 12)),
    "a longer digest": approval.replace(digest, `${digest}ff`),
    "another lane": approval.replace("| AUTH-FEDERATION |", "| AUTH-MFA |"),
    "no date": approval.replace("- 2026-09-27 |", "- today |"),
    "the word elsewhere": `- 2026-09-27 | AUTH-FEDERATION | hosting-smoke ${digest} | オーナー APPROVED | x`,
  };
  for (const [name, line] of Object.entries(refused)) assert.ok(!approved(line, digest), name);
  // A later revocation withdraws it; a later approval restores it.
  const revoked = `- 2026-09-27 | AUTH-FEDERATION | hosting-smoke REVOKED ${digest} | 調整役 | x`;
  assert.ok(!approved(`${approval}\n${revoked}`, digest));
  assert.ok(approved(`${revoked}\n${approval}`, digest));
  assert.ok(approved(`${approval}\n${revoked}\n${approval}`, digest));
  // The digest covers the module that names the project, by absolute path.
  const read = [];
  await scriptDigest(async (path) => {
    read.push(path);
    return "";
  });
  assert.ok(read.some((path) => path.endsWith("/auth-account/harness.mjs")));
  assert.ok(SOURCES.every((path) => path.startsWith("/") && existsSync(path)));
});

test("the uncommitted check works from any directory", async () => {
  const dir = await mkdtemp(join(tmpdir(), "fed-git-"));
  spawnSync("git", ["-C", dir, "init", "-q"]);
  const source = join(dir, "a.mjs");
  const cwd = process.cwd();
  process.chdir(tmpdir());
  try {
    assert.equal(await uncommitted([source]), "");
    await writeFile(source, "1");
    assert.match(await uncommitted([source]), /a\.mjs/);
  } finally {
    process.chdir(cwd);
  }
});

test("the web config must be the sandbox's, with a project number and an API key", () => {
  const web = {
    projectId: SANDBOX_PROJECT,
    projectNumber: "123456789012",
    messagingSenderId: "123456789012",
    apiKey: "fake-api-key-for-the-test-00",
  };
  assert.deepEqual(checkWebConfig(web), [web.apiKey, web.projectNumber]);
  for (const [name, bad] of Object.entries({
    "another project": { ...web, projectId: "fireemu-oracle-sbx" },
    "no number": { ...web, projectNumber: undefined },
    "a number that disagrees": { ...web, messagingSenderId: "1" },
    "no key": { ...web, apiKey: "" },
  })) {
    assert.throws(() => checkWebConfig(bad), /web config/, name);
  }
});

test("the shared sandbox lock is exclusive and released after the run", async () => {
  const dir = await mkdtemp(join(tmpdir(), "fed-lock-"));
  const ledger = join(dir, "sandbox-ledger.jsonl");
  const inside = await withSandboxLock(ledger, async () => {
    assert.match(await readFile(`${ledger}.lock`, "utf8"), new RegExp(TASK_ID));
    await assert.rejects(
      withSandboxLock(ledger, async () => "no"),
      /another run holds/,
    );
    return "done";
  });
  assert.equal(inside, "done");
  assert.ok(!existsSync(`${ledger}.lock`));
  await writeFile(`${ledger}.lock`, "FS-RULES pid 1\n");
  await assert.rejects(
    withSandboxLock(ledger, async () => "no"),
    /FS-RULES pid 1/,
  );
});

test("a run that needs recovery keeps the lock, and only this task's recover takes it", async () => {
  const dir = await mkdtemp(join(tmpdir(), "fed-keep-"));
  const ledger = join(dir, "sandbox-ledger.jsonl");
  const needs = await withSandboxLock(
    ledger,
    async () => ({ run: RUN, outcome: "needs-recovery" }),
    {
      keep: (entry) => entry.outcome === "needs-recovery",
    },
  );
  assert.equal(needs.outcome, "needs-recovery");
  assert.match(
    await readFile(`${ledger}.lock`, "utf8"),
    new RegExp(`${TASK_ID} needs-recovery run ${RUN}`),
  );
  // Another lane cannot start; this task's recover takes the lock over and releases it.
  await assert.rejects(
    withSandboxLock(ledger, async () => "no"),
    /needs-recovery/,
  );
  await withSandboxLock(ledger, async () => ({ run: RUN, outcome: "recovered" }), {
    keep: (entry) => entry.outcome !== "recovered",
    ours: true,
  });
  assert.ok(!existsSync(`${ledger}.lock`));
  // A lock of another lane is never taken over.
  await writeFile(`${ledger}.lock`, "FS-RULES pid 1\n");
  await assert.rejects(
    withSandboxLock(ledger, async () => "no", { ours: true }),
    /is not this task's/,
  );
  assert.equal(await readFile(`${ledger}.lock`, "utf8"), "FS-RULES pid 1\n");
});

test("recover finds the unfinished run and its authorizedDomains in the ledger", () => {
  const line = (extra) =>
    JSON.stringify({
      ts: "2026-09-27T12:00:00Z",
      project: SANDBOX_PROJECT,
      taskId: TASK_ID,
      ...extra,
    });
  const started = line({
    event: "started",
    run: RUN,
    authorizedDomainsBefore: DOMAINS,
    scriptDigest: "d".repeat(64),
  });
  assert.deepEqual(runToRecover(started), {
    run: RUN,
    before: DOMAINS,
    digest: "d".repeat(64),
    issuerHost: undefined,
  });
  assert.deepEqual(
    runToRecover(`${started}\n${line({ run: RUN, outcome: "needs-recovery", issuerHost: HOST })}`),
    { run: RUN, before: DOMAINS, digest: "d".repeat(64), issuerHost: HOST },
  );
  assert.equal(
    runToRecover(`${started}\n${line({ run: RUN, outcome: "smoke-passed" })}`),
    undefined,
  );
  assert.equal(runToRecover(""), undefined);
  assert.throws(
    () => runToRecover(line({ event: "started", run: RUN })),
    /authorizedDomainsBefore/,
  );
});

test("recover deletes a channel left behind and never writes the Auth config", async () => {
  const fake = fakeSandbox();
  fake.state.channel = true;
  fake.state.served[`/oidc/${RUN}/jwks.json`] = "{}";
  const ledger = [];
  const { call } = limitedFetch(fake.fetchImpl, { run: RUN });
  const recover = (before) =>
    hostingRecover({
      api: call,
      run: RUN,
      before,
      appendLedger: async (entry) => ledger.push(entry),
      sleep: async () => {},
      meta: { token: "fake-token" },
    });
  const entry = await recover(DOMAINS);
  assert.equal(entry.outcome, "recovered", JSON.stringify(entry));
  assert.equal(entry.channelReadBack, "absent");
  assert.equal(entry.issuerHost, HOST);
  assert.equal(entry.issuerGone, true);
  assert.ok(
    !fake.calls.some(({ method, url }) => method !== "GET" && url.includes("identitytoolkit")),
  );
  // Again with nothing left: still recovered. A changed authorizedDomains is not.
  assert.equal((await recover(DOMAINS)).outcome, "recovered");
  assert.equal((await recover([...DOMAINS, HOST])).outcome, "needs-recovery");
  assert.equal(ledger.length, 3);
  assert.ok(ledger.every((line) => line.action === "hosting-recover"));
});

test("the lock stays when a run fails after its started line or while recovering", async () => {
  const dir = await mkdtemp(join(tmpdir(), "fed-fail-"));
  const ledger = join(dir, "sandbox-ledger.jsonl");
  const lock = `${ledger}.lock`;
  const boom = () => {
    throw new Error("ADC expired");
  };
  // Before the started line nothing was sent: the lock goes.
  await assert.rejects(
    withSandboxLock(ledger, async () => boom()),
    /ADC expired/,
  );
  assert.ok(!existsSync(lock));
  // After it the sandbox may be changed: the lock stays and says so.
  await assert.rejects(
    withSandboxLock(ledger, async (state) => {
      state.run = RUN;
      state.started = true;
      boom();
    }),
    /ADC expired/,
  );
  assert.match(await readFile(lock, "utf8"), new RegExp(`${TASK_ID} needs-recovery run ${RUN}`));
  // A recovery that fails keeps it too.
  await assert.rejects(
    withSandboxLock(
      ledger,
      async (state) => {
        state.run = RUN;
        boom();
      },
      { ours: true },
    ),
    /ADC expired/,
  );
  assert.match(await readFile(lock, "utf8"), /needs-recovery/);
});

test("recover takes over only a lock that needs recovery or whose process is gone", async () => {
  const dir = await mkdtemp(join(tmpdir(), "fed-take-"));
  const ledger = join(dir, "sandbox-ledger.jsonl");
  const lock = `${ledger}.lock`;
  const recovered = async () => ({ run: RUN, outcome: "recovered" });
  // A running smoke of this task (this process is alive) is never taken over.
  await writeFile(lock, `${TASK_ID} pid ${process.pid} since now\n`);
  await assert.rejects(
    withSandboxLock(ledger, recovered, { ours: true }),
    /not this task's to recover/,
  );
  assert.match(await readFile(lock, "utf8"), new RegExp(`pid ${process.pid}`));
  // A crashed one is.
  const gone = spawnSync(process.execPath, ["-e", "0"]).pid;
  await writeFile(lock, `${TASK_ID} pid ${gone} since then\n`);
  await withSandboxLock(ledger, recovered, { ours: true });
  assert.ok(!existsSync(lock));
});

test("recover records a failure without deleting and fetches a recorded issuer again", async () => {
  const ledger = [];
  const run = async (fake, extra = {}) => {
    const { call } = limitedFetch(fake.fetchImpl, { run: RUN });
    return hostingRecover({
      api: call,
      run: RUN,
      before: DOMAINS,
      appendLedger: async (entry) => ledger.push(entry),
      sleep: async () => {},
      meta: { token: "fake-token" },
      ...extra,
    });
  };
  const forbidden = fakeSandbox({
    channel: () => reply(403, { error: { message: "PERMISSION_DENIED" } }),
  });
  const entry = await run(forbidden);
  assert.equal(entry.outcome, "needs-recovery");
  assert.match(entry.error, /channel: HTTP 403/);
  assert.equal(ledger.at(-1).action, "hosting-recover");
  assert.ok(!forbidden.calls.some(({ method }) => method === "DELETE"));
  // The channel is gone but its files were cached: the recorded host is fetched again.
  const cached = fakeSandbox({
    issuer: () => reply(200, "{}", { "content-type": "application/json" }),
  });
  const stale = await run(cached, { issuerHost: HOST });
  assert.equal(stale.issuerGone, false);
  assert.equal(stale.outcome, "needs-recovery");
  // A recorded host that is not the run's channel is not fetched.
  const other = fakeSandbox();
  const skipped = await run(other, { issuerHost: "evil.web.app" });
  assert.equal(skipped.issuerHost, undefined);
  assert.equal(skipped.outcome, "recovered");
});

test("a channel create whose answer is lost is probed and removed if it exists", async () => {
  const lost = (exists) =>
    fakeSandbox({
      create: (state) => {
        state.channel = exists;
        throw new TypeError("fetch failed");
      },
    });
  const created = lost(true);
  const one = await smoke(created);
  assert.equal(one.outcome.outcome, "failed-cleaned", JSON.stringify(one.outcome));
  assert.equal(one.outcome.channelReadBack, "absent");
  assert.ok(created.calls.some(({ method }) => method === "DELETE"));
  const absent = lost(false);
  const two = await smoke(absent);
  assert.equal(two.outcome.outcome, "failed-cleaned");
  assert.ok(!absent.calls.some(({ method }) => method === "DELETE"));
  // A probe that cannot tell leaves the run to recovery.
  const unknown = fakeSandbox({
    create: () => {
      throw new TypeError("fetch failed");
    },
    channel: () => reply(503, {}),
  });
  const three = await smoke(unknown);
  assert.equal(three.outcome.outcome, "needs-recovery");
  assert.match(three.outcome.channelProbe, /503/);
  assert.ok(three.used.api <= LIMITS.api);
});

test("requests never follow a redirect", async () => {
  const seen = [];
  const { call } = limitedFetch(
    async (url, init) => {
      seen.push(init.redirect);
      return reply(200, {});
    },
    { run: RUN },
  );
  await call("https://firebasehosting.googleapis.com/a", { redirect: "follow" });
  await call(`https://${HOST}/x`);
  assert.deepEqual(seen, ["error", "error"]);
});
