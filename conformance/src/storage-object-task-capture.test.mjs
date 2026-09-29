import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { createProductionSecretRegistry } from "./storage-object/production-secret-registry.mjs";
import { sanitizeProductionCapture } from "./storage-object/production-capture-policy.mjs";
import { createProductionCaptureProfile } from "./storage-object/production-capture-coverage.mjs";

const profile = {
  maxValues: 256,
  maxUtf8Bytes: 65536,
  maxIndexNodes: 200000,
  maxScanCodeUnits: 16777216,
};
const hash = (value) => createHash("sha256").update(value).digest("hex");
function fixture(action, changes = {}) {
  const r = createProductionSecretRegistry({ ...profile, ...changes });
  const capture = (input = {}) => {
    const supplied = {
      url: "https://storage.googleapis.com/storage/v1/b/example.appspot.com/o/owned%2Fobject",
      direction: "response",
      complete: true,
      headers: [],
      body: Buffer.from('{"name":"owned/object","generation":"1"}'),
      expectedObjectNames: ["owned/object"],
      expectedBucket: "example.appspot.com",
      secretRegistry: r,
      status: 200,
      ...input,
    };
    const kind = supplied.url.startsWith("https://securetoken.googleapis.com/")
      ? "auth-refresh"
      : supplied.url.startsWith("https://identitytoolkit.googleapis.com/")
        ? "auth-signup"
        : "storage";
    supplied.captureProfile = createProductionCaptureProfile({
      kind,
      objectName: kind === "storage" ? "owned/object" : null,
      method: kind === "storage" ? "GET" : "POST",
      url: supplied.url,
      sessionPhase: null,
    });
    return sanitizeProductionCapture(supplied);
  };
  try {
    action(r, capture);
  } finally {
    r.close();
  }
}

test("task matching retains all eighty-one declared values without truncating to local sixty-four", () =>
  fixture((r, capture) => {
    for (let i = 0; i < 81; i++) r.register(`SYNTHETIC_DECLARED_${i}_PRIVATE`);
    for (const i of [0, 63, 64, 80]) {
      const result = capture({
        body: Buffer.from(
          JSON.stringify({
            name: "owned/object",
            contentDisposition: `prefix SYNTHETIC_DECLARED_${i}_PRIVATE suffix`,
          }),
        ),
      });
      assert.equal(result.body, null);
      assert.equal(result.mode, "COMMITMENT_ONLY");
      assert.equal(result.taskSecretStatus, "AVAILABLE");
    }
    assert.equal(r.snapshot().values, 81);
  }));

test("ordinary Storage body bytes and original SHA remain unchanged with task matching", () =>
  fixture((r, capture) => {
    r.register("SYNTHETIC_UNRELATED_PRIVATE");
    const body = Buffer.from(
      ' { "name" : "owned/object", "generation" : "1", "contentDisposition" : "attachment; filename=ordinary.txt" } ',
    );
    const result = capture({ body });
    assert.equal(result.mode, "RAW_BODY");
    assert.deepEqual(result.body, body);
    assert.equal(result.originalSha256, hash(body));
    assert.equal(result.taskSecretStatus, "AVAILABLE");
  }));

test("body, header and query discoveries protect later captures including encoded copies", () => {
  for (const source of ["body", "header", "query", "unused-credential"])
    fixture((r, capture) => {
      const secret = "SYNTHETIC_TASK_DISCOVERY_+/xyz-123456789";
      const input = {
        body: {
          body: Buffer.from(JSON.stringify({ name: "owned/object", downloadTokens: secret })),
        },
        header: { headers: [["X-Guploader-Uploadid", secret]] },
        query: {
          url: `https://storage.googleapis.com/storage/v1/b/example.appspot.com/o/owned%2Fobject?token=${encodeURIComponent(secret)}`,
        },
        "unused-credential": {
          url: "https://securetoken.googleapis.com/v1/token",
          body: Buffer.from(
            JSON.stringify({
              access_token: secret,
              id_token: "SYNTHETIC_ID_xyz",
              refresh_token: "SYNTHETIC_REFRESH_xyz",
              user_id: "synthetic-uid",
              project_id: "123456789012",
              token_type: "Bearer",
              expires_in: "3600",
            }),
          ),
        },
      }[source];
      assert.equal(capture(input).taskSecretStatus, "AVAILABLE", source);
      for (const copy of [
        secret,
        encodeURIComponent(secret),
        Buffer.from(secret).toString("base64"),
        `prefix-${Buffer.from(secret).toString("base64url")}xx`,
      ]) {
        const result = capture({
          body: Buffer.from(JSON.stringify({ name: "owned/object", contentDisposition: copy })),
        });
        assert.equal(result.body, null, source);
        assert.equal(result.taskSecretStatus, "AVAILABLE", source);
        assert.equal(JSON.stringify(result).includes(secret), false, source);
      }
    });
});

test("all discoveries occur before projecting typed UID or email observations", () =>
  fixture((r, capture) => {
    const result = capture({
      url: "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=SYNTHETIC_API_KEY_xyz",
      expectedEmails: ["storage-object@example.com"],
      body: Buffer.from(
        JSON.stringify({
          localId: "SYNTHETIC_PRIVATE_UID",
          email: "storage-object@example.com",
          idToken: "SYNTHETIC_PRIVATE_UID",
          refreshToken: "SYNTHETIC_REFRESH_xyz",
          expiresIn: "3600",
        }),
      ),
    });
    assert.equal(result.body, null);
    assert.equal(typeof result.observation.localId, "undefined");
    assert.equal(JSON.stringify(result).includes("SYNTHETIC_PRIVATE_UID"), false);
  }));

test("discovery, byte and scan exhaustion commit all data and suppress typed observations", () => {
  for (const changes of [{ maxValues: 1 }, { maxUtf8Bytes: 1 }, { maxScanCodeUnits: 1 }])
    fixture((r, capture) => {
      const secret = "SYNTHETIC_OVERFLOW_xyz";
      const result = capture({
        body: Buffer.from(
          JSON.stringify({ name: "owned/object", downloadTokens: [secret, "SYNTHETIC_NEXT_xyz"] }),
        ),
        headers: [["Content-Disposition", secret]],
      });
      assert.equal(result.mode, "COMMITMENT_ONLY");
      assert.equal(result.body, null);
      assert.equal(result.observation, null);
      assert.equal(result.taskSecretStatus, "UNAVAILABLE");
      assert.equal(JSON.stringify(result).includes(secret), false);
      assert.throws(() => r.openScan(), /SECRET_REGISTRY_UNAVAILABLE/);
    }, changes);
});

test("incomplete or unavailable task registries never resume raw capture", () =>
  fixture((r, capture) => {
    const result = capture({ complete: false });
    assert.equal(result.taskSecretStatus, "UNAVAILABLE");
    assert.equal(result.body, null);
    const later = capture();
    assert.equal(later.mode, "COMMITMENT_ONLY");
    assert.equal(later.taskSecretStatus, "UNAVAILABLE");
    assert.equal(later.body, null);
  }));

test("scan exhaustion caught during URL projection still makes the entire capture unavailable", () =>
  fixture(
    (r, capture) => {
      const result = capture({ body: Buffer.alloc(0) });
      assert.equal(result.taskSecretStatus, "UNAVAILABLE");
      assert.equal(result.body, null);
      assert.equal(result.observation, null);
      assert.throws(() => r.openScan(), /SECRET_REGISTRY_UNAVAILABLE/);
    },
    { maxScanCodeUnits: 1 },
  ));

test("unregistered credential-shaped components commit the whole capture and stop subsequent scans", () => {
  const secret = "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NENT";
  fixture((r, capture) => {
    const body = Buffer.from(
      JSON.stringify({ name: "owned/object", contentDisposition: `prefix[${secret}]suffix` }),
    );
    const result = capture({ body });
    assert.equal(result.mode, "COMMITMENT_ONLY");
    assert.equal(result.body, null);
    assert.equal(result.originalSha256, hash(body));
    assert.equal(result.taskSecretStatus, "UNAVAILABLE");
    assert.equal(result.observation, null);
    assert.equal(JSON.stringify(result).includes(secret), false);
    assert.throws(() => r.openScan(), /SECRET_REGISTRY_UNAVAILABLE/);
    assert.equal(capture().taskSecretStatus, "UNAVAILABLE");
  });
  fixture((r, capture) => {
    r.register(secret);
    const result = capture({
      body: Buffer.from(JSON.stringify({ name: "owned/object", contentDisposition: secret })),
    });
    assert.equal(result.mode, "COMMITMENT_ONLY");
    assert.equal(result.body, null);
    assert.equal(result.taskSecretStatus, "AVAILABLE");
  });
});

for (const encoding of ["raw", "percent", "base64", "base64url-suffix"])
  test(`an overlapping credential never approves an unregistered suffix copy (${encoding})`, () => {
    const prefix = "SYNTHETIC_EXISTING_PREFIX",
      suffix = "SYNTHETIC_NEW_CREDENTIAL_SUFFIX";
    const token = `GOCSPX-${prefix}_${suffix}`;
    const copy = {
      raw: suffix,
      percent: [...Buffer.from(suffix)]
        .map((byte) => `%${byte.toString(16).padStart(2, "0")}`)
        .join(""),
      base64: Buffer.from(suffix).toString("base64"),
      "base64url-suffix": `prefix[${Buffer.from(suffix).toString("base64url")}]backup`,
    }[encoding];
    fixture((r, capture) => {
      r.register(prefix);
      const first = capture({
        body: Buffer.from(JSON.stringify({ name: "owned/object", contentDisposition: token })),
      });
      const later = capture({
        body: Buffer.from(JSON.stringify({ name: "owned/object", contentDisposition: copy })),
      });
      assert.equal(later.body, null);
      assert.equal(later.taskSecretStatus, "UNAVAILABLE");
      assert.equal(first.mode, "COMMITMENT_ONLY");
      assert.equal(first.taskSecretStatus, "UNAVAILABLE");
      assert.equal(first.observation, null);
      assert.equal(first.url.pathname, null);
      assert.deepEqual(first.headers, []);
      assert.throws(() => r.openScan(), /SECRET_REGISTRY_UNAVAILABLE/);
    });
    fixture((r, capture) => {
      r.register(token);
      const result = capture({
        body: Buffer.from(JSON.stringify({ name: "owned/object", contentDisposition: token })),
      });
      assert.equal(result.body, null);
      assert.equal(result.taskSecretStatus, "AVAILABLE");
    });
  });

test("a copied registry is rejected before any registry callback", () =>
  fixture((r, capture) => {
    let hooks = 0;
    const forged = {
      ...r,
      openScan() {
        hooks++;
        return r.openScan();
      },
    };
    assert.throws(() => capture({ secretRegistry: forged }), /invalid production capture/);
    assert.equal(hooks, 0);
    assert.equal(r.snapshot().closed, false);
  }));
