import assert from "node:assert/strict";
import test from "node:test";
import { createProductionSecretRegistry } from "./storage-object/production-secret-registry.mjs";
const limits = {
  maxValues: 81,
  maxUtf8Bytes: 65536,
  maxIndexNodes: 200000,
  maxScanCodeUnits: 16777216,
};
function lines(secret, text) {
  const registry = createProductionSecretRegistry(limits);
  try {
    registry.register(secret);
    const scan = registry.openScan();
    assert.equal(typeof scan.findSecretCopyLines, "function");
    return scan.findSecretCopyLines(text);
  } finally {
    registry.close();
  }
}
for (const [name, secret, text, expected] of [
  ["raw", "alpha", "safe\nalpha\nend", [2]],
  ["cross-line", "alpha\nbeta", "safe\nalpha\nbeta\nend", [2, 3]],
  ["percent", "雪", "safe\n%e9%9B%aa\nend", [2]],
  ["percent-cross-line", "雪\n花", "safe\n%e9%9B%aa\n%e8%8a%B1\nend", [2, 3]],
  ["form", "a b", "safe\na+b\nend", [2]],
  ["mixed-form", "a b c", "safe\n%61%20b+c\nend", [2]],
  [
    "base64",
    "synthetic-secret",
    "safe\n" + Buffer.from("synthetic-secret").toString("base64") + "\nend",
    [2],
  ],
  ["base64-percent", "雪", "safe\n" + Buffer.from("%e9%9B%aa").toString("base64") + "\nend", [2]],
  [
    "percent-base64",
    "synthetic-secret",
    "safe\n" +
      [...Buffer.from("synthetic-secret").toString("base64")]
        .map((c) => "%" + c.charCodeAt(0).toString(16))
        .join("") +
      "\nend",
    [2],
  ],
  [
    "source-line-not-decoded-line",
    "a\nb",
    "safe\n" + Buffer.from("a\nb").toString("base64") + "\nend",
    [2],
  ],
  ["short-digit", "1", "1\nsafe\n1\n", [1, 3]],
  ["repeated", "alpha", "alpha alpha\nsafe\nalpha", [1, 3]],
  ["no-copy", "synthetic-secret", "safe\nempty\n", []],
])
  test(`line locations cover ${name} without returning observed values`, () => {
    const result = lines(secret, text);
    assert.deepEqual(result, {
      lineNumbers: expected,
      matchedLineCount: expected.length,
      truncated: false,
    });
    assert.deepEqual(Object.keys(result).toSorted(), [
      "lineNumbers",
      "matchedLineCount",
      "truncated",
    ]);
  });
test("line reports count every distinct affected line while returning at most twenty", () => {
  const result = lines("needle", Array.from({ length: 25 }, (_, i) => "needle " + i).join("\n"));
  assert.deepEqual(
    result.lineNumbers,
    Array.from({ length: 20 }, (_, i) => i + 1),
  );
  assert.equal(result.matchedLineCount, 25);
  assert.equal(result.truncated, true);
});

test("failure links retain suffix matches before the longer registered word completes", () => {
  const registry = createProductionSecretRegistry(limits);
  try {
    registry.register("needle");
    registry.register("xneedlex");
    assert.deepEqual(
      registry.openScan().findSecretCopyLines("safe\nxneedle\nend").lineNumbers,
      [2],
    );
  } finally {
    registry.close();
  }
});
test("an embedded noncanonical base64 alignment is located on its source line", () => {
  const text = "safe\nAA" + Buffer.from("xneedleY").toString("base64") + "\nend";
  assert.deepEqual(lines("needle", text).lineNumbers, [2]);
});
test("typed array accounting includes complete terminal and inherited pattern lengths", () => {
  const registry = createProductionSecretRegistry(limits);
  assert.equal(registry.snapshot().index.typedArrayBytes, limits.maxIndexNodes * 22);
  registry.close();
  assert.equal(registry.snapshot().index.typedArrayBytes, 0);
});
for (const [name, value] of [
  [
    "object",
    {
      toString() {
        throw new Error("hook must not run");
      },
    },
  ],
  ["surrogate", "\ud800"],
  ["oversize", "x".repeat(2097153)],
])
  test(`the ${name} location input halts the original index without coercion`, () => {
    const registry = createProductionSecretRegistry(limits);
    try {
      registry.register("needle");
      assert.throws(
        () => registry.openScan().findSecretCopyLines(value),
        /SECRET_REGISTRY_UNAVAILABLE/,
      );
      assert.equal(registry.snapshot().failed, true);
    } finally {
      registry.close();
    }
  });
test("line scanning charges cumulative transformation and location work before allocating outside its limit", () => {
  const registry = createProductionSecretRegistry({ ...limits, maxScanCodeUnits: 32 });
  try {
    registry.register("needle");
    assert.throws(
      () => registry.openScan().findSecretCopyLines("safe\nneedle\nend"),
      /SECRET_REGISTRY_UNAVAILABLE/,
    );
    assert.equal(registry.snapshot().failed, true);
  } finally {
    registry.close();
  }
});
test("boolean and line detection agree for mixed encodings and malformed UTF-8 replacements", () => {
  const registry = createProductionSecretRegistry(limits);
  try {
    for (const secret of ["needle", "雪", "a b", "\ufffd", "alpha\nbeta"])
      registry.register(secret);
    const examples = [
      "safe",
      "prefix needle suffix",
      "alpha\nbeta",
      "%e9%9B%aa",
      "a+b",
      "%FF",
      "%e9%9B%aa%FF",
    ];
    for (let i = 0; i < 256; i++)
      examples.push(
        "safe\n" +
          Buffer.from([i, 0xe0, 0xa0, 0xff, 0xc3, 0x80, 10, 65]).toString("base64") +
          "\nend",
      );
    for (const text of examples) {
      const boolean = registry.openScan().hasSecretCopy(text);
      const location = registry.openScan().findSecretCopyLines(text);
      assert.equal(location.matchedLineCount > 0, boolean, text);
    }
  } finally {
    registry.close();
  }
});
