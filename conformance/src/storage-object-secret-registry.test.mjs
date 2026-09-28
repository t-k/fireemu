import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";
import {
  captureHasSecretCopy,
  captureSecretForms,
} from "./storage-object/production-capture-body.mjs";
import { isProductionSecretScan } from "./storage-object/production-secret-index.mjs";

const module = await import("./storage-object/production-secret-registry.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const profile = {
  maxValues: 128,
  maxUtf8Bytes: 65536,
  maxIndexNodes: 32768,
  maxScanCodeUnits: 1048576,
};
function registry(changes = {}) {
  assert.equal(
    typeof module.createProductionSecretRegistry,
    "function",
    "bounded task registry is missing",
  );
  return module.createProductionSecretRegistry({ ...profile, ...changes });
}

test("task secrets deduplicate by value and enforce exact count before the next value", () => {
  const r = registry({ maxValues: 2 });
  try {
    r.register("SYNTHETIC_ALPHA");
    r.register("SYNTHETIC_BETA");
    r.register("SYNTHETIC_ALPHA");
    assert.equal(r.snapshot().values, 2);
    assert.equal(r.snapshot().failed, false);
    assert.throws(() => r.register("SYNTHETIC_GAMMA"), /SECRET_REGISTRY_UNAVAILABLE/);
    assert.equal(r.snapshot().values, 2);
    assert.equal(r.snapshot().failed, true);
    assert.throws(() => r.openScan(), /SECRET_REGISTRY_UNAVAILABLE/);
  } finally {
    r.close();
  }
});

test("a pure profile retains more than sixty-four distinct values and original identities", () => {
  const r = registry({ maxValues: 81 });
  try {
    for (let i = 0; i < 81; i++) r.register(`SYNTHETIC_DECLARED_${i}_PRIVATE`);
    assert.equal(r.snapshot().values, 81);
    assert.equal(module.isProductionSecretRegistry(r), true);
    assert.equal(module.isProductionSecretRegistry({ ...r }), false);
    const scan = r.openScan();
    assert.equal(isProductionSecretScan(scan), true);
    assert.equal(isProductionSecretScan({ ...scan }), false);
    assert.equal(scan.hasSecretCopy("later SYNTHETIC_DECLARED_0_PRIVATE copied"), true);
    assert.equal(scan.hasSecretCopy("later SYNTHETIC_DECLARED_80_PRIVATE copied"), true);
    assert.throws(() => r.register("SYNTHETIC_NEXT_PRIVATE"), /SECRET_REGISTRY_UNAVAILABLE/);
    assert.throws(() => scan.hasSecretCopy("ordinary text"), /SECRET_REGISTRY_UNAVAILABLE/);
  } finally {
    r.close();
  }
});

test("the memory bound counts UTF-8 bytes and permits the exact byte boundary", () => {
  const r = registry({ maxValues: 3, maxUtf8Bytes: 6 });
  try {
    r.register("é");
    r.register("🙂");
    r.register("é");
    assert.equal(r.snapshot().utf8Bytes, 6);
    assert.equal(r.snapshot().values, 2);
    assert.throws(() => r.register("x"), /SECRET_REGISTRY_UNAVAILABLE/);
    assert.equal(r.snapshot().utf8Bytes, 6);
    assert.equal(r.snapshot().failed, true);
  } finally {
    r.close();
  }
});

test("retaining a small caller slice does not retain its large backing string", () => {
  const script = `
    import { createProductionSecretRegistry } from ${JSON.stringify(new URL("./storage-object/production-secret-registry.mjs", import.meta.url).href)};
    const collect = () => {
      for (let i = 0; i < 3; i++) global.gc();
      return process.memoryUsage().heapUsed;
    };
    const before = collect();
    const r = createProductionSecretRegistry({
      maxValues: 1, maxUtf8Bytes: 128, maxIndexNodes: 4096, maxScanCodeUnits: 1048576,
    });
    function input() {
      const parent = "a".repeat(32 * 1024 * 1024) + "z";
      return parent.slice(1000, 1128);
    }
    r.register(input());
    await new Promise(setImmediate);
    const retained = collect(), snapshot = r.snapshot();
    r.close();
    await new Promise(setImmediate);
    const afterClose = collect();
    process.stdout.write(JSON.stringify({
      retainedDelta: retained - before, releasedDelta: retained - afterClose,
      count: snapshot.values, utf8Bytes: snapshot.utf8Bytes, failed: snapshot.failed,
    }));
  `;
  const result = JSON.parse(
    execFileSync(process.execPath, ["--expose-gc", "--input-type=module", "--eval", script], {
      encoding: "utf8",
      env: {},
      timeout: 10000,
      maxBuffer: 4096,
    }),
  );
  assert.equal(result.count, 1);
  assert.equal(result.utf8Bytes, 128);
  assert.equal(result.failed, false);
  assert.equal(result.retainedDelta < 8 * 1024 * 1024, true, JSON.stringify(result));
  assert.equal(result.releasedDelta < 8 * 1024 * 1024, true, JSON.stringify(result));
});

test("a bounded index recognizes raw, mixed-percent and embedded Base64 copies", () => {
  const r = registry(),
    secret = "SYNTHETIC_PRIVATE_+/é_xyz";
  try {
    r.register(secret);
    const encoded = encodeURIComponent(secret),
      mixed = encoded.replaceAll("S", "%53").replaceAll("%2F", "%2f");
    const copies = [
      secret,
      encoded,
      mixed,
      Buffer.from(secret).toString("base64"),
      `prefix-${Buffer.from(mixed).toString("base64url")}xx`,
      `prefix${Buffer.from(mixed).toString("base64url")}xx`,
      JSON.parse(JSON.stringify(secret).replace("S", "\\u0053")),
    ];
    const scan = r.openScan();
    for (const copy of copies) assert.equal(scan.hasSecretCopy(`attachment; value=${copy}`), true);
    assert.equal(scan.hasSecretCopy("ordinary nonsecret text"), false);
    assert.equal(r.snapshot().failed, false);
    assert.equal(JSON.stringify(r.snapshot()).includes(secret), false);
    assert.equal(scan.snapshot().scanCodeUnits > 0, true);
  } finally {
    r.close();
  }
});

test("failure links find suffix patterns and subsequent registrations join existing scans", () => {
  const r = registry();
  try {
    for (const value of ["he", "she", "hers", "his", "xabcZ", "abc"]) r.register(value);
    const scan = r.openScan();
    assert.equal(scan.hasSecretCopy("ushers"), true);
    assert.equal(scan.hasSecretCopy("xyz"), false);
    assert.equal(scan.hasSecretCopy("xabc"), true);
    r.register("later-private-value");
    assert.equal(scan.hasSecretCopy("prefix-later-private-value-suffix"), true);
    assert.equal(r.snapshot().values, 7);
  } finally {
    r.close();
  }
});

test("index exhaustion latches failure and never admits a partial pattern", () => {
  const r = registry({ maxIndexNodes: 1 });
  try {
    assert.throws(() => r.register("SYNTHETIC_INDEX_OVERFLOW"), /SECRET_REGISTRY_UNAVAILABLE/);
    assert.equal(r.snapshot().values, 0);
    assert.equal(r.snapshot().failed, true);
    assert.throws(() => r.register("x"), /SECRET_REGISTRY_UNAVAILABLE/);
    assert.throws(() => r.openScan(), /SECRET_REGISTRY_UNAVAILABLE/);
  } finally {
    r.close();
  }
});

test("the exact index boundary preserves matching before the next new edge fails", () => {
  const calibration = registry();
  calibration.register("private/A_+/");
  const nodeCount = calibration.snapshot().index.nodes;
  calibration.close();
  const r = registry({ maxIndexNodes: nodeCount });
  try {
    r.register("private/A_+/");
    assert.equal(r.snapshot().index.nodes, nodeCount);
    assert.equal(r.openScan().hasSecretCopy("prefix private/A_+/ suffix"), true);
    assert.throws(() => r.register("🙂"), /SECRET_REGISTRY_UNAVAILABLE/);
    assert.equal(r.snapshot().values, 1);
    assert.equal(r.snapshot().failed, true);
  } finally {
    r.close();
  }
});

test("one capture scan shares its work cap and exhaustion stops all later scans", () => {
  const r = registry({ maxScanCodeUnits: 10 });
  try {
    r.register("long-secret");
    const scan = r.openScan();
    assert.equal(scan.hasSecretCopy("!"), false);
    assert.equal(scan.hasSecretCopy("!"), false);
    assert.equal(scan.snapshot().scanCodeUnits, 10);
    assert.throws(() => scan.hasSecretCopy("!"), /SECRET_REGISTRY_UNAVAILABLE/);
    assert.equal(r.snapshot().failed, true);
    assert.throws(() => r.openScan(), /SECRET_REGISTRY_UNAVAILABLE/);
  } finally {
    r.close();
  }
});

test("failure-link compilation exhaustion stops every scan within the exact index capacity", () => {
  const patterns = Array.from(
    { length: 256 },
    (_, i) => "a".repeat(1024) + String.fromCharCode(0x100 + i),
  );
  const limits = { maxValues: 256, maxUtf8Bytes: 1048576, maxIndexNodes: 200000 };
  const calibration = registry(limits);
  for (const value of patterns) calibration.register(value);
  const exactNodes = calibration.snapshot().index.nodes;
  calibration.close();
  const r = registry({ ...limits, maxIndexNodes: exactNodes });
  try {
    for (const value of patterns) r.register(value);
    assert.equal(r.snapshot().index.nodes, exactNodes);
    assert.equal(r.snapshot().values, patterns.length);
    assert.equal(r.snapshot().failed, false);
    const scan = r.openScan();
    assert.throws(
      () => scan.hasSecretCopy("ordinary nonsecret text"),
      /SECRET_REGISTRY_UNAVAILABLE/,
    );
    assert.equal(r.snapshot().failed, true);
    assert.throws(() => scan.hasSecretCopy("ordinary text"), /SECRET_REGISTRY_UNAVAILABLE/);
    assert.throws(() => r.openScan(), /SECRET_REGISTRY_UNAVAILABLE/);
  } finally {
    r.close();
  }
});

test("original scans reject boxed values and closed registries without coercion hooks", () => {
  const r = registry();
  let hooks = 0;
  try {
    r.register("SYNTHETIC_CLOSED_SECRET");
    const scan = r.openScan(),
      proxy = Proxy.revocable(
        {},
        {
          get() {
            hooks++;
          },
        },
      );
    proxy.revoke();
    assert.throws(() => scan.hasSecretCopy(proxy.proxy), /SECRET_REGISTRY_UNAVAILABLE/);
    assert.equal(hooks, 0);
  } finally {
    r.close();
  }
  const other = registry();
  other.register("SYNTHETIC_OTHER_SECRET");
  const scan = other.openScan();
  other.close();
  assert.throws(() => scan.hasSecretCopy("SYNTHETIC_OTHER_SECRET"), /SECRET_REGISTRY_UNAVAILABLE/);
  assert.throws(
    () =>
      other.register({
        toString() {
          hooks++;
          return "secret";
        },
      }),
    /SECRET_REGISTRY_UNAVAILABLE/,
  );
  assert.equal(hooks, 0);
  assert.equal(other.snapshot().closed, true);
});

test("registry configuration rejects accessors, proxies and unbounded profiles without hooks", () => {
  assert.equal(typeof module.createProductionSecretRegistry, "function");
  let hooks = 0;
  const getter = { ...profile };
  Object.defineProperty(getter, "maxValues", {
    enumerable: true,
    get() {
      hooks++;
      return 128;
    },
  });
  const proxy = Proxy.revocable({}, {});
  proxy.revoke();
  for (const input of [
    getter,
    proxy.proxy,
    { ...profile, maxValues: Infinity },
    { ...profile, maxIndexNodes: 1048577 },
    { ...profile, extra: true },
  ])
    assert.throws(
      () => module.createProductionSecretRegistry(input),
      /invalid secret registry configuration/,
    );
  assert.equal(hooks, 0);
});

test("indexed matching preserves the bounded reference detector across deterministic encodings", () => {
  const r = registry(),
    secrets = Array.from({ length: 12 }, (_, i) => `private/${i}_+end`);
  try {
    for (const secret of secrets) r.register(secret);
    const forms = secrets.flatMap(captureSecretForms);
    for (let i = 0; i < 120; i++) {
      const secret = secrets[i % secrets.length],
        value =
          i % 5 === 0
            ? `ordinary-${i}`
            : [
                secret,
                encodeURIComponent(secret),
                Buffer.from(secret).toString("base64"),
                `prefix-${Buffer.from(encodeURIComponent(secret)).toString("base64url")}xx`,
              ][i % 4];
      const scan = r.openScan(),
        text = `attachment; ${value}; suffix`;
      assert.equal(scan.hasSecretCopy(text), captureHasSecretCopy(text, forms));
    }
  } finally {
    r.close();
  }
});
