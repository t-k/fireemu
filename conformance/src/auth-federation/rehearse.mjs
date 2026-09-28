// A rehearsal of the production recording (`record.mjs`) with nothing sent to Google: the
// Identity Toolkit and Secure Token requests go to a local fireemu (strict profile), the
// Hosting and Service Usage APIs and the issuer's host are a fake in this process, and the
// ledger is a temporary file. It runs the same `recordCampaign`, the same counted fetch and
// the same guard, and writes the fixture under `.runs/`, never over the committed one.
//
//   node src/auth-federation/rehearse.mjs          (spawns `fireemu exec`)

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

import { SANDBOX_PROJECT } from "../auth-account/harness.mjs";
import { CONFORMANCE_DIR } from "../config.mjs";
import { resolveFireemuBinary } from "../evidence.mjs";
import { limitedFetch } from "./hosting.mjs";
import { discoveryDocument, jwksDocument } from "./idp.mjs";
import { makeCertificate, prepareKeys } from "./run.mjs";
import { LIMITS, recordCampaign, scanFixture } from "./record.mjs";

const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "auth-federation");
const HOSTING = "firebasehosting.googleapis.com";
const reply = (status, body, headers = {}) =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers });

/**
 * The fake of the sandbox's Hosting and Service Usage APIs and of the run's channel host:
 * one channel, one version, the files a release publishes by path.
 */
export function fakeHosting(run) {
  const host = `${SANDBOX_PROJECT}--fed-${run}-rehearse.web.app`;
  const version = `sites/${SANDBOX_PROJECT}/versions/rehearsal`;
  const state = { channel: false, versionDeleted: false, uploads: {}, hashes: {}, served: {} };
  const handle = async (url, init = {}) => {
    const method = init.method ?? "GET";
    const u = new URL(url);
    if (u.host === host) {
      return state.channel && state.served[u.pathname]
        ? reply(200, state.served[u.pathname], { "content-type": "application/json" })
        : reply(404, "not found");
    }
    if (u.host === "serviceusage.googleapis.com") return reply(200, { state: "ENABLED" });
    if (u.host === `upload-${HOSTING}`) {
      state.uploads[u.pathname.split("/").at(-1)] = init.body;
      return reply(200, {});
    }
    const path = u.pathname.replace("/v1beta1/", "");
    if (method === "GET" && path === `projects/${SANDBOX_PROJECT}/sites/${SANDBOX_PROJECT}`) {
      return reply(200, { name: path, type: "DEFAULT_SITE" });
    }
    if (method === "GET" && path.endsWith("/channels")) return reply(200, { channels: [] });
    if (method === "POST" && path.endsWith("/channels")) {
      state.channel = true;
      return reply(200, { name: `${path}/fed-${run}`, url: `https://${host}` });
    }
    if (method === "POST" && path.endsWith("/versions")) {
      state.versionLabels = JSON.parse(init.body ?? "{}").labels ?? {};
      state.versionCreated = true;
      return reply(200, { name: version });
    }
    if (method === "GET" && path === `sites/${SANDBOX_PROJECT}/versions`) {
      const versions = [...(state.otherVersions ?? [])];
      if (state.versionCreated && !state.versionDeleted) {
        versions.push({ name: version, labels: state.versionLabels, status: "CREATED" });
      }
      return reply(200, { versions });
    }
    if (path.endsWith(":populateFiles")) {
      state.hashes = JSON.parse(init.body).files;
      return reply(200, {
        uploadUrl: `https://upload-${HOSTING}/upload/${version}/files`,
        uploadRequiredHashes: Object.values(state.hashes),
      });
    }
    if (method === "PATCH" && path === version) return reply(200, {});
    if (method === "POST" && path.endsWith("/releases")) {
      state.released = true;
      for (const [file, hash] of Object.entries(state.hashes)) {
        state.served[file] = gunzipSync(state.uploads[hash]).toString("utf8");
      }
      return reply(200, {});
    }
    if (method === "DELETE" && path.endsWith(`/channels/fed-${run}`)) {
      state.channel = false;
      return reply(200, {});
    }
    if (method === "GET" && path.endsWith(`/channels/fed-${run}`)) {
      return state.channel
        ? reply(200, {
            url: `https://${host}`,
            ...(state.released ? { release: { version: { name: version } } } : {}),
          })
        : reply(404, {});
    }
    if (method === "DELETE" && path === version) {
      state.versionDeleted = true;
      return reply(200, {});
    }
    if (method === "GET" && path === version) {
      return state.versionDeleted ? reply(404, {}) : reply(200, { status: "FINALIZED" });
    }
    return reply(500, { unexpected: `${method} ${url}` });
  };
  return { host, handle, state };
}

/**
 * A fetch that sends the Identity Toolkit and Secure Token requests to the local emulator
 * and everything else to the fake. The emulator's answers get a `Date` when they lack one
 * (the precheck reads it); `dated` counts how often that happened.
 */
export function rehearsalFetch(origin, hosting) {
  const dated = { added: 0 };
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url);
    if (["identitytoolkit.googleapis.com", "securetoken.googleapis.com"].includes(u.host)) {
      const { redirect: _redirect, ...rest } = init;
      const response = await fetch(`${origin}/${u.host}${u.pathname}${u.search}`, rest);
      if (response.headers.get("date")) return response;
      dated.added += 1;
      const headers = new Headers(response.headers);
      headers.set("date", new Date().toUTCString());
      return new Response(await response.text(), { status: response.status, headers });
    }
    return hosting.handle(url, init);
  };
  return { fetchImpl, dated };
}

/** Inside `fireemu exec`: the recording against the local emulator and the fake. */
async function sessionRehearsal() {
  const prepared = JSON.parse(await readFile(process.env.REHEARSAL_IN, "utf8"));
  const { privateKey, jwk } = prepared.keys.run;
  const { createPrivateKey } = await import("node:crypto");
  const keys = {
    run: { privateKey: createPrivateKey(privateKey), jwk },
    other: {
      privateKey: createPrivateKey(prepared.keys.other.privateKey),
      jwk: prepared.keys.other.jwk,
    },
  };
  const hosting = fakeHosting(prepared.run);
  const { fetchImpl, dated } = rehearsalFetch(
    `http://${process.env.FIREBASE_AUTH_EMULATOR_HOST}`,
    hosting,
  );
  const { call, used } = limitedFetch(fetchImpl, { run: prepared.run, limits: LIMITS });
  const ledger = [];
  let fixture;
  const entry = await recordCampaign({
    api: call,
    run: prepared.run,
    keys,
    certificatePem: prepared.certificatePem,
    meta: {
      adminToken: "owner",
      apiKey: "fake-api-key",
      projectNumber: "123456789012",
      gitSha: "rehearsal",
      digest: "0".repeat(64),
      envelopeId: "rehearsal",
      startedAt: new Date().toISOString(),
    },
    appendLedger: async (line) => ledger.push({ ...line, requests: { ...used } }),
    writeFixture: async (built) => {
      const text = `${JSON.stringify(built, null, 2)}\n`;
      // Only local fakes are in it: kept even when the scan refuses it, to see why.
      await writeFile(join(RUN_DIR, "rehearsal-fixture.json"), text);
      scanFixture(text, ["fake-api-key", "123456789012"]);
      fixture = built;
    },
    stop: { check() {} },
    now: () => Math.floor(Date.now() / 1000),
    sleep: async () => {},
  });
  await writeFile(
    process.env.REHEARSAL_OUT,
    JSON.stringify({
      entry,
      ledger,
      fixture,
      used,
      datesAdded: dated.added,
      hosting: hosting.state.channel,
    }),
  );
}

async function rehearse() {
  await mkdir(RUN_DIR, { recursive: true, mode: 0o700 });
  const run = createHash("sha256").update(String(Date.now())).digest("hex").slice(0, 6);
  const keys = prepareKeys();
  const secretDir = await mkdtemp(join(tmpdir(), "fireemu-rehearsal-"));
  try {
    const certificatePem = await makeCertificate(secretDir, "saml-a");
    const issuer = `https://${SANDBOX_PROJECT}--fed-${run}-rehearse.web.app/oidc/${run}`;
    const exportKey = (key) => ({
      privateKey: key.privateKey.export({ format: "pem", type: "pkcs8" }),
      jwk: key.jwk,
    });
    const inPath = join(secretDir, "in.json");
    const outPath = join(RUN_DIR, "rehearsal.json");
    const configPath = join(secretDir, "fireemu.config.json");
    await writeFile(
      inPath,
      JSON.stringify({
        run,
        certificatePem,
        keys: { run: exportKey(keys.run), other: exportKey(keys.other) },
      }),
      { mode: 0o600 },
    );
    await writeFile(
      configPath,
      JSON.stringify({
        schemaVersion: 1,
        profile: "strict",
        daemon: { authProjectNumbers: { [SANDBOX_PROJECT]: "123456789012" } },
        auth: {
          idTokenSigning: "session-rsa",
          apiKeys: ["fake-api-key"],
          idpSigners: {
            [issuer]: {
              ...jwksDocument(keys.run.jwk),
              authorization_endpoint: discoveryDocument(issuer).authorization_endpoint,
            },
          },
        },
      }),
    );
    const binary = resolveFireemuBinary();
    const child = spawn(
      binary,
      [
        "exec",
        "--config",
        configPath,
        "--project",
        SANDBOX_PROJECT,
        "--only",
        "auth",
        "--http-port",
        "0",
        "--firestore-port",
        "0",
        "--ui-port",
        "0",
        "--hub-port",
        "0",
        "--logging-port",
        "0",
        "--",
        process.execPath,
        fileURLToPath(import.meta.url),
        "session",
      ],
      {
        cwd: CONFORMANCE_DIR,
        stdio: ["ignore", "ignore", "inherit"],
        env: { ...process.env, REHEARSAL_IN: inPath, REHEARSAL_OUT: outPath },
      },
    );
    const code = await new Promise((resolve) => child.once("exit", resolve));
    if (code !== 0) throw new Error(`fireemu session exited ${code}`);
    const out = JSON.parse(await readFile(outPath, "utf8"));
    console.log(
      JSON.stringify(
        {
          outcome: out.entry.outcome,
          programFailures: out.entry.programFailures,
          stepRequests: out.entry.stepRequests,
          used: out.used,
          accountsCreated: out.entry.accountsCreated,
          programs: Object.keys(out.fixture?.programs ?? {}).length,
          datesAdded: out.datesAdded,
          cleanup: {
            channelReadBack: out.entry.channelReadBack,
            versionStatus: out.entry.versionStatus,
            providersLeft: out.entry.providersLeft,
            accountsLeft: out.entry.accountsLeft,
            configUnchanged: out.entry.configUnchanged,
          },
        },
        null,
        2,
      ),
    );
  } finally {
    await rm(secretDir, { recursive: true, force: true });
  }
}

const mode = process.argv[1] === fileURLToPath(import.meta.url) ? process.argv[2] : undefined;
if (mode === "session") await sessionRehearsal();
else if (mode === undefined && process.argv[1] === fileURLToPath(import.meta.url)) await rehearse();
else if (mode !== undefined) throw new Error(`unknown mode ${mode}`);
