import assert from "node:assert/strict";
import test from "node:test";
import {
  createProductionSecretRegistry,
  productionSecretRegistryHasValue,
} from "./storage-object/production-secret-registry.mjs";

const module = await import("./storage-object/production-secret-discovery.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const profile = {
  maxValues: 256,
  maxUtf8Bytes: 65536,
  maxIndexNodes: 200000,
  maxScanCodeUnits: 1048576,
};
const capture = (changes = {}) => ({
  url: "https://storage.googleapis.com/storage/v1/b/example.appspot.com/o/owned",
  direction: "response",
  headers: [["Content-Type", "application/json"]],
  body: Buffer.from("{}"),
  complete: true,
  bodyKind: "json",
  ...changes,
});
function discover(r, value) {
  assert.equal(
    typeof module.discoverProductionCaptureSecrets,
    "function",
    "task discovery is missing",
  );
  return module.discoverProductionCaptureSecrets(r, value);
}
function fixture(action, changes = {}) {
  const r = createProductionSecretRegistry({ ...profile, ...changes });
  try {
    action(r);
  } finally {
    r.close();
  }
}

test("JSON discovery precedes schema projection and retains unused credential fields", () =>
  fixture((r) => {
    const secrets = [
      "SYNTHETIC_UNUSED_ACCESS_abc",
      "SYNTHETIC_PASSWORD_HASH_xyz",
      "SYNTHETIC_SALT_xyz",
    ];
    const result = discover(
      r,
      capture({
        url: "https://securetoken.googleapis.com/v1/token?key=SYNTHETIC_QUERY_API_KEY",
        body: Buffer.from(
          JSON.stringify({
            access_token: secrets[0],
            users: [{ passwordHash: secrets[1], salt: secrets[2] }],
          }),
        ),
      }),
    );
    assert.equal(result.available, true);
    assert.equal(result.bodyForm, "JSON");
    assert.equal(result.discoveredValues, 4);
    for (const secret of [...secrets, "SYNTHETIC_QUERY_API_KEY"])
      assert.equal(r.openScan().hasSecretCopy(`later ${secret}`), true);
    assert.equal(JSON.stringify(result).includes("SYNTHETIC"), false);
  }));
test("configuration discovery retains unused signer, salt separator, SMTP and client credentials", () =>
  fixture((r) => {
    const values = [
      "SYNTHETIC_SIGNER_PRIVATE",
      "SYNTHETIC_SEPARATOR_PRIVATE",
      "SYNTHETIC_SMTP_PRIVATE",
      "SYNTHETIC_API_KEY_PRIVATE",
      "SYNTHETIC_RAW_PASSWORD_PRIVATE",
      "SYNTHETIC_SMTP_USERNAME_PRIVATE",
    ];
    const result = discover(
      r,
      capture({
        url: "https://identitytoolkit.googleapis.com/admin/v2/projects/example-project/config",
        body: Buffer.from(
          JSON.stringify({
            signIn: {
              hashConfig: {
                signerKey: Buffer.from(values[0]).toString("base64"),
                saltSeparator: Buffer.from(values[1]).toString("base64"),
              },
            },
            notification: { sendEmail: { smtp: { password: values[2], username: values[5] } } },
            client: { apiKey: values[3] },
            users: [{ rawPassword: values[4] }],
          }),
        ),
      }),
    );
    assert.equal(result.available, true);
    for (const value of values) {
      assert.equal(productionSecretRegistryHasValue(r, value), true);
      assert.equal(
        r.openScan().hasSecretCopy(Buffer.from(`prefix-${value}-suffix`).toString("base64url")),
        true,
      );
    }
  }));

test("binary hash configuration retains each canonical Base64 spelling without replacement decoding", () => {
  const bytes = Buffer.from([255, 250, 0, 129]);
  const standard = bytes.toString("base64"),
    encodedUrl = bytes.toString("base64url");
  const forms = [
    standard,
    standard.replace(/=+$/, ""),
    encodedUrl,
    encodedUrl + "=".repeat((4 - (encodedUrl.length % 4)) % 4),
  ];
  for (const input of forms)
    fixture((r) => {
      const result = discover(
        r,
        capture({ body: Buffer.from(JSON.stringify({ signerKey: input })) }),
      );
      assert.equal(result.available, true);
      for (const form of forms) assert.equal(productionSecretRegistryHasValue(r, form), true);
      assert.equal(productionSecretRegistryHasValue(r, bytes.toString("utf8")), false);
      assert.equal(r.snapshot().values, new Set(forms).size);
    });
});

test("noncanonical hash configuration encoding closes the task instead of forgiving invalid bytes", () => {
  for (const value of ["%%%", "YQ===", "YQ= ", "Y", "YWJj\n", "YWJj."])
    fixture((r) => {
      const result = discover(
        r,
        capture({ body: Buffer.from(JSON.stringify({ saltSeparator: value })) }),
      );
      assert.equal(result.available, false);
      assert.equal(result.reason, "SECRET_DISCOVERY_UNAVAILABLE");
      assert.throws(() => r.openScan(), /SECRET_REGISTRY_UNAVAILABLE/);
    });
});

test("CSV, authorization and opaque URI discovery covers whole values and each capability", () =>
  fixture((r) => {
    const first = "SYNTHETIC_DOWNLOAD_ONE_xyz",
      second = "SYNTHETIC_DOWNLOAD_TWO_xyz";
    const uri =
      "https://storage.googleapis.com/upload/storage/v1/b/example.appspot.com/o?upload_id=SYNTHETIC_UPLOAD_ID_xyz";
    const result = discover(
      r,
      capture({
        headers: [
          ["Authorization", "firebase SYNTHETIC_AUTH_xyz"],
          ["X-Goog-Upload-URL", uri],
          ["X-Firebase-Storage-Download-Tokens", `${first},${second}`],
        ],
        body: Buffer.from(
          JSON.stringify({ metadata: { firebaseStorageDownloadTokens: `${first},${second}` } }),
        ),
      }),
    );
    assert.equal(result.available, true);
    for (const secret of [
      first,
      second,
      `${first},${second}`,
      uri,
      "SYNTHETIC_UPLOAD_ID_xyz",
      "SYNTHETIC_AUTH_xyz",
      "firebase SYNTHETIC_AUTH_xyz",
    ])
      assert.equal(r.openScan().hasSecretCopy(`later ${secret}`), true);
  }));

test("field order cannot hide a copy from discovery and earlier recordings remain searchable", () =>
  fixture((r) => {
    const secret = "SYNTHETIC_EARLIER_CAPABILITY_+/xyz";
    for (const body of [
      { contentDisposition: secret, downloadTokens: [secret] },
      { downloadTokens: [secret], contentDisposition: secret },
    ])
      assert.equal(
        discover(r, capture({ body: Buffer.from(JSON.stringify(body)) })).available,
        true,
      );
    assert.equal(
      discover(r, capture({ body: Buffer.from(JSON.stringify({ size: "0" })) })).available,
      true,
    );
    assert.equal(r.snapshot().values, 1);
    assert.equal(
      r.openScan().hasSecretCopy(`prefix-${Buffer.from(secret).toString("base64url")}xx`),
      true,
    );
  }));

test("strict credential forms discover refresh and client secrets without returning their values", () =>
  fixture((r) => {
    const result = discover(
      r,
      capture({
        url: "https://oauth2.googleapis.com/token",
        direction: "request",
        headers: [["content-type", "application/x-www-form-urlencoded;charset=UTF-8"]],
        body: Buffer.from(
          "grant_type=refresh_token&client_id=public-client&client_secret=SYNTHETIC_CLIENT%2BSECRET&refresh_token=SYNTHETIC_REFRESH%2FTOKEN",
        ),
      }),
    );
    assert.equal(result.available, true);
    assert.equal(result.bodyForm, "FORM");
    assert.equal(result.discoveredValues, 2);
    for (const secret of ["SYNTHETIC_CLIENT+SECRET", "SYNTHETIC_REFRESH/TOKEN"])
      assert.equal(r.openScan().hasSecretCopy(secret), true);
  }));

test("one capture permits its exact local discovery bound and stops before the next distinct value", () => {
  const values = Array.from({ length: 64 }, (_, i) => `SYNTHETIC_CAPTURE_${i}_xyz`);
  fixture((r) => {
    assert.equal(
      discover(r, capture({ body: Buffer.from(JSON.stringify({ downloadTokens: values })) }))
        .available,
      true,
    );
    assert.equal(r.snapshot().values, 64);
  });
  fixture((r) => {
    const scan = r.openScan();
    const result = discover(
      r,
      capture({
        body: Buffer.from(
          JSON.stringify({ downloadTokens: [...values, "SYNTHETIC_NEXT_CAPTURE_xyz"] }),
        ),
      }),
    );
    assert.equal(result.available, false);
    assert.equal(result.reason, "SECRET_DISCOVERY_UNAVAILABLE");
    assert.throws(() => r.openScan(), /SECRET_REGISTRY_UNAVAILABLE/);
    assert.throws(() => scan.hasSecretCopy("ordinary"), /SECRET_REGISTRY_UNAVAILABLE/);
  });
});

test("incomplete, malformed and unsupported encoded shapes stop the original task registry", () => {
  for (const value of [
    capture({ complete: false }),
    capture({ body: Buffer.from('{"downloadTokens":"first","downloadTokens":"second"}') }),
    capture({ body: Buffer.from("not JSON") }),
    capture({
      body: Buffer.from([123, 34, 105, 100, 84, 111, 107, 101, 110, 34, 58, 34, 255, 34, 125]),
    }),
    capture({ body: Buffer.from('{"idToken":{"unexpected":"shape"}}') }),
    capture({ url: "https://storage.googleapis.com/o?token=one&token=two" }),
    capture({ url: "https://unknown.example/o?token=secret" }),
    capture({
      url: "https://oauth2.googleapis.com/token",
      direction: "request",
      headers: [["Content-Type", "application/x-www-form-urlencoded"]],
      body: Buffer.from("refresh_token=one&refresh_token=two"),
    }),
  ])
    fixture((r) => {
      assert.equal(discover(r, value).available, false);
      assert.throws(() => r.openScan(), /SECRET_REGISTRY_UNAVAILABLE/);
    });
});

test("invalid capture accessors, proxies and Buffer hooks are never called", () => {
  let hooks = 0;
  const accessor = capture();
  Object.defineProperty(accessor, "body", {
    enumerable: true,
    get() {
      hooks++;
      return Buffer.from("{}");
    },
  });
  const pair = ["Authorization", "SYNTHETIC_PRIVATE"];
  Object.defineProperty(pair, "1", {
    enumerable: true,
    get() {
      hooks++;
      return "SYNTHETIC_PRIVATE";
    },
  });
  const body = Buffer.from('{"refreshToken":"SYNTHETIC_BUFFER_HOOK_xyz"}');
  body.valueOf = () => {
    hooks++;
    return body;
  };
  body.toString = () => {
    hooks++;
    return "{}";
  };
  for (const key of ["length", "byteLength"])
    Object.defineProperty(body, key, {
      get() {
        hooks++;
        return 0;
      },
    });
  fixture((r) => {
    assert.equal(discover(r, capture({ body })).available, true);
    assert.equal(r.openScan().hasSecretCopy("SYNTHETIC_BUFFER_HOOK_xyz"), true);
  });
  const proxy = Proxy.revocable({}, {});
  proxy.revoke();
  const activeProxy = new Proxy(capture(), {
    getPrototypeOf() {
      hooks++;
      return Object.prototype;
    },
  });
  for (const value of [
    activeProxy,
    accessor,
    proxy.proxy,
    capture({ headers: [pair] }),
    capture({ body: proxy.proxy }),
  ])
    fixture((r) => assert.equal(discover(r, value).available, false));
  assert.equal(hooks, 0);
});

test("copied registry methods cannot acquire discovery authority", () =>
  fixture((r) => {
    assert.equal(typeof module.discoverProductionCaptureSecrets, "function");
    assert.throws(
      () => module.discoverProductionCaptureSecrets({ ...r }, capture()),
      /invalid task secret registry/,
    );
    assert.equal(r.snapshot().closed, false);
  }));

test("registry resource exhaustion returns fixed evidence and stops future scans", () =>
  fixture(
    (r) => {
      const result = discover(
        r,
        capture({
          body: Buffer.from(
            '{"idToken":"SYNTHETIC_FIRST_xyz","refreshToken":"SYNTHETIC_SECOND_xyz"}',
          ),
        }),
      );
      assert.equal(result.available, false);
      assert.equal(result.reason, "SECRET_DISCOVERY_UNAVAILABLE");
      assert.equal(JSON.stringify(result).includes("SYNTHETIC"), false);
      assert.throws(() => r.openScan(), /SECRET_REGISTRY_UNAVAILABLE/);
    },
    { maxValues: 1 },
  ));

test("discovery accepts the exact two-MiB body boundary and rejects the next byte", () => {
  const overhead = Buffer.byteLength(JSON.stringify({ padding: "" }));
  for (const delta of [0, 1])
    fixture((r) => {
      const body = Buffer.from(
        JSON.stringify({ padding: "a".repeat(2 * 1024 * 1024 + delta - overhead) }),
      );
      assert.equal(body.length, 2 * 1024 * 1024 + delta);
      const result = discover(r, capture({ body }));
      assert.equal(result.available, delta === 0);
      assert.equal(r.snapshot().values, 0);
      if (delta) assert.throws(() => r.openScan(), /SECRET_REGISTRY_UNAVAILABLE/);
    });
});
