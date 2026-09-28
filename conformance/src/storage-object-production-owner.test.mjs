import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
const module = await import("./storage-object/production-owner.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const hash = (value) => createHash("sha256").update(value).digest("hex");
const principal = {
  subject: "fixture-owner-subject",
  clientId: "fixture-client.apps.googleusercontent.com",
  requiredScopes: ["https://www.googleapis.com/auth/cloud-platform"],
};
const adc = {
  type: "authorized_user",
  client_id: principal.clientId,
  client_secret: "SYNTHETIC_CLIENT_SECRET",
  refresh_token: "SYNTHETIC_REFRESH_SECRET",
  quota_project_id: "example-project",
};
const token = "SYNTHETIC_OWNER_ACCESS_TOKEN";

async function fixture(action, changes = {}) {
  assert.equal(
    typeof module.createProductionOwnerState,
    "function",
    "production owner state is missing",
  );
  const directory = mkdtempSync(join(tmpdir(), "storage-object-owner-state-"));
  chmodSync(directory, 0o700);
  const path = join(directory, "adc.json"),
    bytes = Buffer.from(JSON.stringify(adc));
  writeFileSync(path, bytes, { mode: 0o600 });
  const calls = [],
    proofs = [],
    secrets = [];
  let state;
  const controls = Object.freeze({
    send: async (id, request) => {
      calls.push({ id, request });
      let data;
      if (id.endsWith("owner-exchange")) {
        const form = new URLSearchParams(request.body.toString());
        assert.equal(form.get("refresh_token"), adc.refresh_token);
        assert.equal(form.get("client_secret"), adc.client_secret);
        data = { access_token: token, token_type: "Bearer", expires_in: 3600 };
      } else {
        const context = {
          recording: 1,
          kind: "owner-tokeninfo",
          phase: id.includes("cleanup-renewal") ? "cleanup" : "subject",
          operationId: `r1/control/${hash(id)}`,
        };
        assert.equal(state.ownerAuthorization(context), `Bearer ${token}`);
        assert.equal(request.body.length, 0);
        data = {
          sub: principal.subject,
          azp: principal.clientId,
          aud: principal.clientId,
          scope: principal.requiredScopes.join(" "),
          expires_in: 3600,
        };
      }
      return { status: 200, arrayBuffer: async () => Buffer.from(JSON.stringify(data)) };
    },
  });
  try {
    state = module.createProductionOwnerState({
      recording: 1,
      adcInput: {
        path,
        expectedSha256: hash(bytes),
        expectedClientId: principal.clientId,
        expectedQuotaProjectId: "example-project",
      },
      principal,
      controls,
      verifyAdmission: () => true,
      onProof: async (row) => proofs.push(row),
      onSecret: (value) => {
        secrets.push(value);
      },
      ...changes,
    });
    await action({ state, calls, proofs, secrets, directory, path });
  } finally {
    state?.close();
    rmSync(directory, { recursive: true });
  }
}
const normalContext = () => ({
  recording: 1,
  kind: "storage",
  phase: "subject",
  operationId: `r1/p1/${"a".repeat(64)}`,
});

test("owner state connects a pinned ADC exchange to the same tokeninfo token and prior principal", async () => {
  await fixture(async ({ state, calls, proofs, secrets, directory }) => {
    assert.throws(
      () => state.ownerAuthorization(normalContext()),
      /^Error: production owner is unavailable$/,
    );
    await state.exchangeAndProve("initial");
    assert.equal(calls.length, 2);
    assert.equal(state.ownerAuthorization(normalContext()), `Bearer ${token}`);
    assert.deepEqual(
      calls.map((row) => row.id),
      ["r1/initial-owner-exchange", "r1/initial-owner-tokeninfo"],
    );
    assert.deepEqual(readdirSync(directory), ["adc.json"]);
    assert.equal(proofs.length, 1);
    assert.equal(Object.isFrozen(proofs[0]), true);
    for (const secret of [token, adc.client_secret, adc.refresh_token])
      assert.equal(JSON.stringify(proofs).includes(secret), false);
    assert.equal(proofs[0].accessTokenSha256, hash(token));
    assert.equal(proofs[0].adcSha256, hash(Buffer.from(JSON.stringify(adc))));
    assert.deepEqual(secrets, [adc.client_secret, adc.refresh_token, token]);
  });
});

test("three declared exchange pairs are single-use and no extra refresh or reread is added", async () => {
  await fixture(async ({ state, calls, path }) => {
    await assert.rejects(state.exchangeAndProve("cleanup-renewal"), /owner stage/);
    await state.exchangeAndProve("initial");
    await assert.rejects(state.exchangeAndProve("initial"), /owner stage/);
    writeFileSync(path, "changed after the initial pinned read");
    const capability = Object.freeze({});
    await state.exchangeAndProve("subject-renewal", capability);
    await state.exchangeAndProve("cleanup-renewal", capability);
    assert.equal(calls.length, 6);
    assert.equal(calls[2].request.recipeToken, capability);
    assert.equal(calls[4].request.recipeToken, capability);
    await assert.rejects(state.exchangeAndProve("cleanup-renewal", capability), /owner stage/);
    await assert.rejects(state.exchangeAndProve("recovery", capability), /owner stage/);
    assert.equal(calls.length, 6);
  });
});

test("missing admission rejects before an ADC read or a control request", async () => {
  await fixture(
    async ({ state, calls, proofs, secrets, path }) => {
      let reads = 0;
      const original = fs.openSync;
      fs.openSync = (...args) => {
        if (args[0] === path) reads++;
        return original(...args);
      };
      syncBuiltinESMExports();
      try {
        await assert.rejects(
          state.exchangeAndProve("initial"),
          /^Error: production owner is unavailable$/,
        );
        assert.equal(reads, 0);
        assert.equal(calls.length, 0);
        assert.equal(secrets.length, 0);
        assert.equal(proofs.length, 0);
      } finally {
        fs.openSync = original;
        syncBuiltinESMExports();
      }
    },
    { verifyAdmission: () => false },
  );
});

test("tokeninfo mismatch fails before publishing an owner credential and cannot be retried", async () => {
  for (const change of [
    { sub: "another-owner" },
    { aud: "another-client" },
    { azp: "another-client" },
    { scope: "openid" },
    { expires_in: 60 },
  ]) {
    let calls = 0;
    await fixture(
      async ({ state, proofs }) => {
        await assert.rejects(
          state.exchangeAndProve("initial"),
          /^Error: production owner is unavailable$/,
        );
        assert.throws(
          () => state.ownerAuthorization(normalContext()),
          /^Error: production owner is unavailable$/,
        );
        await assert.rejects(
          state.exchangeAndProve("initial"),
          /^Error: production owner is unavailable$/,
        );
        assert.equal(calls, 2);
        assert.equal(proofs.length, 0);
      },
      {
        controls: Object.freeze({
          send: async (id) => {
            calls++;
            return {
              status: 200,
              arrayBuffer: async () =>
                Buffer.from(
                  JSON.stringify(
                    id.endsWith("owner-exchange")
                      ? { access_token: token, token_type: "Bearer", expires_in: 3600 }
                      : {
                          sub: principal.subject,
                          azp: principal.clientId,
                          aud: principal.clientId,
                          scope: principal.requiredScopes[0],
                          expires_in: 3600,
                          ...change,
                        },
                  ),
                ),
            };
          },
        }),
      },
    );
  }
});

test("pending tokeninfo permits only its exact request context", async () => {
  let state,
    calls = 0,
    admissionChecks = 0;
  await fixture(
    async (f) => {
      state = f.state;
      await state.exchangeAndProve("initial");
      assert.equal(calls, 2);
    },
    {
      verifyAdmission: (context) => {
        admissionChecks++;
        return context.phase === "subject";
      },
      controls: Object.freeze({
        send: async (id) => {
          calls++;
          if (id.endsWith("owner-tokeninfo")) {
            for (const context of [
              normalContext(),
              {
                recording: 2,
                kind: "owner-tokeninfo",
                phase: "subject",
                operationId: `r1/control/${hash(id)}`,
              },
              {
                recording: 1,
                kind: "owner-tokeninfo",
                phase: "cleanup",
                operationId: `r1/control/${hash(id)}`,
              },
              {
                recording: 1,
                kind: "owner-tokeninfo",
                phase: "subject",
                operationId: `r1/control/${"0".repeat(64)}`,
              },
            ]) {
              const before = admissionChecks;
              assert.throws(
                () => state.ownerAuthorization(context),
                /^Error: production owner is unavailable$/,
              );
              assert.equal(admissionChecks, before);
            }
          }
          return {
            status: 200,
            arrayBuffer: async () =>
              Buffer.from(
                JSON.stringify(
                  id.endsWith("owner-exchange")
                    ? { access_token: token, token_type: "Bearer", expires_in: 3600 }
                    : {
                        sub: principal.subject,
                        azp: principal.clientId,
                        aud: principal.clientId,
                        scope: principal.requiredScopes[0],
                        expires_in: 3600,
                      },
                ),
              ),
          };
        },
      }),
    },
  );
});

test("control accessors and Proxy functions reject without executing their hooks", async () => {
  let reads = 0;
  await assert.rejects(
    fixture(async () => {}, {
      controls: Object.defineProperty({}, "send", {
        enumerable: true,
        get() {
          reads++;
          return async () => {};
        },
      }),
    }),
    /^Error: invalid production owner configuration$/,
  );
  assert.equal(reads, 0);
  await assert.rejects(
    fixture(async () => {}, {
      verifyAdmission: new Proxy(() => true, {
        apply() {
          reads++;
          return true;
        },
      }),
    }),
    /^Error: invalid production owner configuration$/,
  );
  assert.equal(reads, 0);
});

test("ADC client identity is pinned to the prior principal before any credential read", async () => {
  await assert.rejects(
    fixture(async () => {}, { principal: { ...principal, clientId: "different-prior-client" } }),
    /^Error: invalid production owner configuration$/,
  );
});

test("a valid context's admission refusal irreversibly stops cached credentials and renewal", async () => {
  for (const throws of [false, true]) {
    let allowed = true;
    await fixture(
      async ({ state, calls }) => {
        await state.exchangeAndProve("initial");
        allowed = false;
        assert.throws(() => state.ownerAuthorization(normalContext()), /unavailable/);
        allowed = true;
        assert.throws(() => state.ownerAuthorization(normalContext()), /unavailable/);
        await assert.rejects(state.exchangeAndProve("subject-renewal", {}), /unavailable/);
        assert.equal(state.snapshot().failed, true);
        assert.equal(state.snapshot().hasVerifiedOwner, false);
        assert.equal(calls.length, 2);
      },
      {
        verifyAdmission: () => {
          if (!allowed && throws) throw new Error("RAW_ADMISSION_SECRET");
          return allowed;
        },
      },
    );
  }
});

test("close inside the first secret registration prevents later registration and dispatch", async () => {
  let state,
    registrations = 0;
  await fixture(
    async (f) => {
      state = f.state;
      await assert.rejects(state.exchangeAndProve("initial"), /unavailable/);
      assert.equal(registrations, 1);
      assert.equal(f.calls.length, 0);
      assert.equal(f.proofs.length, 0);
      assert.equal(state.snapshot().closed, true);
      assert.equal(state.snapshot().hasVerifiedOwner, false);
    },
    {
      onSecret: () => {
        registrations++;
        state.close();
      },
    },
  );
});

test("close while reading a late exchange response prevents token registration and tokeninfo", async () => {
  let state,
    calls = 0;
  await fixture(
    async (f) => {
      state = f.state;
      await assert.rejects(state.exchangeAndProve("initial"), /unavailable/);
      assert.equal(calls, 1);
      assert.deepEqual(f.secrets, [adc.client_secret, adc.refresh_token]);
      assert.equal(f.proofs.length, 0);
      assert.equal(state.snapshot().hasVerifiedOwner, false);
    },
    {
      controls: Object.freeze({
        send: async () => {
          calls++;
          return {
            status: 200,
            arrayBuffer: async () => {
              state.close();
              return Buffer.from(
                JSON.stringify({ access_token: token, token_type: "Bearer", expires_in: 3600 }),
              );
            },
          };
        },
      }),
    },
  );
});

test("expires, backward monotonic clocks, failed proof and close stop credentials without automatic HTTP", async () => {
  const descriptor = Object.getOwnPropertyDescriptor(performance, "now");
  let time = 1000;
  Object.defineProperty(performance, "now", { configurable: true, value: () => time });
  try {
    await fixture(async ({ state, calls }) => {
      await state.exchangeAndProve("initial");
      time += 3540000;
      assert.throws(
        () => state.ownerAuthorization(normalContext()),
        /^Error: production owner is unavailable$/,
      );
      assert.equal(calls.length, 2);
      state.close();
      assert.throws(
        () => state.ownerAuthorization(normalContext()),
        /^Error: production owner is unavailable$/,
      );
    });
    time = 1000;
    await fixture(async ({ state, calls }) => {
      await state.exchangeAndProve("initial");
      time = 999;
      assert.throws(
        () => state.ownerAuthorization(normalContext()),
        /^Error: production owner is unavailable$/,
      );
      assert.equal(calls.length, 2);
    });
    time = 1000;
    await fixture(
      async ({ state }) => {
        await state.exchangeAndProve("initial");
        time = 62000;
        assert.throws(
          () => state.ownerAuthorization(normalContext()),
          /^Error: production owner is unavailable$/,
        );
      },
      {
        controls: Object.freeze({
          send: async (id) => ({
            status: 200,
            arrayBuffer: async () =>
              Buffer.from(
                JSON.stringify(
                  id.endsWith("owner-exchange")
                    ? { access_token: token, token_type: "Bearer", expires_in: 121 }
                    : {
                        sub: principal.subject,
                        azp: principal.clientId,
                        aud: principal.clientId,
                        scope: principal.requiredScopes[0],
                        expires_in: 3600,
                      },
                ),
              ),
          }),
        }),
      },
    );
  } finally {
    if (descriptor) Object.defineProperty(performance, "now", descriptor);
    else delete performance.now;
  }
  await fixture(
    async ({ state, calls }) => {
      await assert.rejects(
        state.exchangeAndProve("initial"),
        /^Error: production owner is unavailable$/,
      );
      assert.throws(
        () => state.ownerAuthorization(normalContext()),
        /^Error: production owner is unavailable$/,
      );
      assert.equal(calls.length, 2);
    },
    {
      onProof: async () => {
        throw new Error("SYNTHETIC_PROOF_SECRET");
      },
    },
  );
});
