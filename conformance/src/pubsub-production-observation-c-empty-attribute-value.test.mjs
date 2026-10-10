import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import test from "node:test";
import protobuf from "protobufjs/minimal.js";
import { compareEmptyAttributeValueDisposition } from "./pubsub-observation-c/empty-attribute-value-disposition.mjs";
const fixturePath = process.env.PUBSUB_C_N7_RAW_FIXTURE_MANIFEST;
const fixtures = fixturePath ? JSON.parse(readFileSync(fixturePath)) : [];
const hash = (raw) => createHash("sha256").update(raw).digest("hex");
function fixture(record) {
  const sourceBody = readFileSync(record.source.path),
    localBody = readFileSync(record.local.path);
  for (const [side, raw] of [
    ["source", sourceBody],
    ["local", localBody],
  ]) {
    assert.equal(raw.length, record[side].bytes);
    assert.equal(hash(raw), record[side].sha256);
  }
  const metadata = {
    runId: "567e1cd860a1",
    sourceHead: "a".repeat(40),
    packetSha256: "b".repeat(64),
    descriptorSha256: "c".repeat(64),
  };
  const runtimeInputs = { binarySha256: "d".repeat(64), inputsSha256: "e".repeat(64) };
  const reply = (raw) => ({
    ok: true,
    unknown: false,
    status: 200,
    bodyBytes: raw.length,
    bodySha256: hash(raw),
  });
  return {
    input: { metadata, runtimeInputs },
    cell: { id: "N7" },
    source: {
      n: record.sourceN,
      requestId: record.requestId,
      method: "Pull",
      transport: "grpc",
      reply: reply(sourceBody),
    },
    actual: reply(localBody),
    sourceBody,
    localBody,
    disposition: {
      owner1209: {
        proposalSha256: "71bd68a98cc6914915719dc499c616be2ecf518b18e71c51b5add7e3c16920d4",
        rowSha256WithLf: "a94f604cf2213de67b9413281cc50a5dfb3083348fc71e80f60013d1c07a9228",
      },
      proofIndexSha256: "5af9b45bce6882fb869b37dd721c9ae57908b14964909ee9793dc8515ef8c31d",
      source: { ...metadata },
      runtimeInputs: { ...runtimeInputs },
      cells: ["N7"],
    },
  };
}
test(
  "C N7 empty attribute value uses the four authenticated original bodies",
  { skip: !fixturePath },
  () => {
    assert.equal(fixtures.length, 2);
    for (const record of fixtures) {
      const f = fixture(record),
        before = {
          ...structuredClone(f),
          sourceBody: Buffer.from(f.sourceBody),
          localBody: Buffer.from(f.localBody),
        };
      const proof = compareEmptyAttributeValueDisposition(f);
      assert.equal(proof.verdict, "MATCH");
      assert.equal(proof.physicalVerdict, "DIVERGES");
      assert.deepEqual(f, before);
    }
  },
);
test(
  "C N7 empty attribute value rejects scope, authority, runtime and missing raw near misses",
  { skip: !fixturePath },
  async (t) => {
    const cases = [
      ["other cell", (f) => (f.cell.id = "N8"), null],
      ["other coordinate", (f) => f.source.n++, null],
      ["other request", (f) => f.source.requestId++, null],
      ["other run", (f) => (f.input.metadata.runId = "other"), null],
      [
        "wrong owner",
        (f) => (f.disposition.owner1209.rowSha256WithLf = "f".repeat(64)),
        "NOT_COMPARABLE",
      ],
      [
        "wrong proposal",
        (f) => (f.disposition.owner1209.proposalSha256 = "f".repeat(64)),
        "NOT_COMPARABLE",
      ],
      [
        "wrong proof index",
        (f) => (f.disposition.proofIndexSha256 = "f".repeat(64)),
        "NOT_COMPARABLE",
      ],
      ["wrong source", (f) => (f.disposition.source.sourceHead = "f".repeat(40)), "NOT_COMPARABLE"],
      [
        "wrong runtime",
        (f) => (f.disposition.runtimeInputs.binarySha256 = "f".repeat(64)),
        "NOT_COMPARABLE",
      ],
      ["missing runtime", (f) => delete f.input.runtimeInputs, "NOT_COMPARABLE"],
      ["unknown", (f) => (f.actual.unknown = true), "NOT_COMPARABLE"],
      ["missing raw", (f) => (f.localBody = undefined), "NOT_COMPARABLE"],
      ["wrong hash", (f) => (f.actual.bodySha256 = "f".repeat(64)), "NOT_COMPARABLE"],
      ["wrong length", (f) => f.actual.bodyBytes++, "NOT_COMPARABLE"],
      ["wrong source raw", (f) => (f.sourceBody = f.localBody), "NOT_COMPARABLE"],
    ];
    for (const [name, mutate, expected] of cases)
      await t.test(name, () => {
        const f = fixture(fixtures[0]);
        mutate(f);
        const p = compareEmptyAttributeValueDisposition(f);
        assert.equal(p?.verdict ?? null, expected);
      });
  },
);
test(
  "C N7 empty attribute value retains non-attribute bytes and unknown fields",
  { skip: !fixturePath },
  async (t) => {
    for (const [name, mutate] of [
      [
        "payload",
        (raw) =>
          rewrite(
            raw,
            [
              [1, 1],
              [2, 0],
              [1, 0],
            ],
            (payload) => {
              const bytes = Buffer.from(payload);
              assert.ok(bytes.length > 0);
              bytes[0] ^= 1;
              return bytes;
            },
          ),
      ],
      ["unknown field", (raw) => Buffer.concat([raw, Buffer.from([0x78, 0])])],
      ["truncated", (raw) => raw.subarray(0, raw.length - 1)],
    ])
      await t.test(name, () => {
        const f = fixture(fixtures[0]);
        f.localBody = mutate(f.localBody);
        f.actual.bodyBytes = f.localBody.length;
        f.actual.bodySha256 = hash(f.localBody);
        assert.equal(compareEmptyAttributeValueDisposition(f).verdict, "DIVERGES");
      });
  },
);

// Mutate authenticated local bytes through the existing protobuf reader/writer;
// retain every unselected field byte and recompute only containing lengths.
function fields(raw) {
  const reader = protobuf.Reader.create(raw),
    result = [];
  while (reader.pos < reader.len) {
    const start = reader.pos,
      tag = reader.uint32(),
      number = tag >>> 3,
      wire = tag & 7;
    const payload = wire === 2 ? Buffer.from(reader.bytes()) : (reader.skipType(wire), null);
    result.push({ number, wire, tag, payload, raw: raw.subarray(start, reader.pos) });
  }
  return result;
}
function rewrite(raw, path, mutate) {
  if (!path.length) return mutate(raw);
  const [[number, occurrence], ...rest] = path;
  let count = 0,
    found = false;
  const changed = fields(raw).map((f) => {
    if (f.number !== number || count++ !== occurrence) return f.raw;
    assert.equal(f.wire, 2);
    found = true;
    return Buffer.from(
      protobuf.Writer.create()
        .uint32(f.tag)
        .bytes(rewrite(f.payload, rest, mutate))
        .finish(),
    );
  });
  assert.ok(found);
  return Buffer.concat(changed);
}
const target = [
  [1, 1],
  [2, 0],
  [2, 0],
];
function mutated(f, change) {
  f.localBody = change(f.localBody);
  f.actual.bodyBytes = f.localBody.length;
  f.actual.bodySha256 = hash(f.localBody);
  return f;
}
test(
  "C N7 empty attribute value permits explicit empty local value with necessary ancestor lengths",
  { skip: !fixturePath },
  () => {
    for (const record of fixtures) {
      const f = mutated(fixture(record), (raw) =>
        rewrite(raw, target, (entry) =>
          Buffer.concat([
            entry,
            Buffer.from(protobuf.Writer.create().uint32(18).string("").finish()),
          ]),
        ),
      );
      assert.equal(compareEmptyAttributeValueDisposition(f).verdict, "MATCH");
    }
  },
);
test(
  "C N7 empty attribute value rejects duplicate, missing, typed and foreign attribute layouts",
  { skip: !fixturePath },
  async (t) => {
    const cases = [
      [
        "duplicate key",
        (raw) => rewrite(raw, target, (entry) => Buffer.concat([entry, fields(entry)[0].raw])),
      ],
      [
        "duplicate value",
        (raw) =>
          rewrite(raw, target, (entry) =>
            Buffer.concat([
              entry,
              Buffer.from(
                protobuf.Writer.create().uint32(18).string("").uint32(18).string("").finish(),
              ),
            ]),
          ),
      ],
      [
        "duplicate map entry",
        (raw) =>
          rewrite(
            raw,
            [
              [1, 1],
              [2, 0],
            ],
            (message) => Buffer.concat([message, fields(message).find((f) => f.number === 2).raw]),
          ),
      ],
      [
        "missing key",
        (raw) =>
          rewrite(raw, target, (entry) =>
            Buffer.concat(
              fields(entry)
                .filter((f) => f.number !== 1)
                .map((f) => f.raw),
            ),
          ),
      ],
      [
        "missing map entry",
        (raw) =>
          rewrite(
            raw,
            [
              [1, 1],
              [2, 0],
            ],
            (message) =>
              Buffer.concat(
                fields(message)
                  .filter((f) => f.number !== 2)
                  .map((f) => f.raw),
              ),
          ),
      ],
      [
        "nonempty value",
        (raw) =>
          rewrite(raw, target, (entry) =>
            Buffer.concat([
              entry,
              Buffer.from(protobuf.Writer.create().uint32(18).string("nonempty").finish()),
            ]),
          ),
      ],
      [
        "wrong value type",
        (raw) =>
          rewrite(raw, target, (entry) =>
            Buffer.concat([
              entry,
              Buffer.from(protobuf.Writer.create().uint32(16).uint32(0).finish()),
            ]),
          ),
      ],
      [
        "unknown entry field",
        (raw) =>
          rewrite(raw, target, (entry) =>
            Buffer.concat([
              entry,
              Buffer.from(protobuf.Writer.create().uint32(24).uint32(0).finish()),
            ]),
          ),
      ],
      [
        "foreign key",
        (raw) =>
          rewrite(raw, target, () =>
            Buffer.from(protobuf.Writer.create().uint32(10).string("other").finish()),
          ),
      ],
      [
        "other empty value coordinate",
        (raw) =>
          rewrite(
            raw,
            [
              [1, 0],
              [2, 0],
              [2, 0],
            ],
            () => Buffer.from(protobuf.Writer.create().uint32(10).string("env").finish()),
          ),
      ],
      [
        "unknown message field",
        (raw) =>
          rewrite(
            raw,
            [
              [1, 1],
              [2, 0],
            ],
            (message) =>
              Buffer.concat([
                message,
                Buffer.from(protobuf.Writer.create().uint32(48).uint32(0).finish()),
              ]),
          ),
      ],
      [
        "extra containing length",
        (raw) =>
          rewrite(
            raw,
            [
              [1, 1],
              [2, 0],
            ],
            (message) => Buffer.concat([message, Buffer.from([0])]),
          ),
      ],
    ];
    for (const [name, change] of cases)
      await t.test(name, () => {
        for (const record of fixtures)
          assert.equal(
            compareEmptyAttributeValueDisposition(mutated(fixture(record), change)).verdict,
            "DIVERGES",
          );
      });
  },
);
test(
  "C N7 empty attribute value rejects generated nonempty values and out-of-bound actual raw",
  { skip: !fixturePath },
  () => {
    for (const value of [
      "x",
      "0",
      "env",
      "test",
      "\u0000",
      "日本語",
      "x".repeat(127),
      "x".repeat(128),
    ]) {
      const f = mutated(fixture(fixtures[0]), (raw) =>
        rewrite(raw, target, (entry) =>
          Buffer.concat([
            entry,
            Buffer.from(protobuf.Writer.create().uint32(18).string(value).finish()),
          ]),
        ),
      );
      assert.equal(compareEmptyAttributeValueDisposition(f).verdict, "DIVERGES");
    }
    const f = fixture(fixtures[0]);
    f.localBody = Buffer.alloc(1024 * 1024 + 1);
    f.actual.bodyBytes = f.localBody.length;
    f.actual.bodySha256 = hash(f.localBody);
    assert.equal(compareEmptyAttributeValueDisposition(f).verdict, "NOT_COMPARABLE");
  },
);

const secondFixturePath = process.env.PUBSUB_C_N7_SECOND_SOURCE_FIXTURE_MANIFEST;
const secondFixtures = secondFixturePath ? JSON.parse(readFileSync(secondFixturePath)) : [];
function secondSourceFixture(record) {
  const sourceBody = readFileSync(record.source.path);
  assert.equal(sourceBody.length, record.source.bytes);
  assert.equal(hash(sourceBody), record.source.sha256);
  const metadata = {
    runId: "45298b949da0",
    sourceHead: "a".repeat(40),
    packetSha256: "b".repeat(64),
    descriptorSha256: "c".repeat(64),
  };
  const runtimeInputs = { binarySha256: "d".repeat(64), inputsSha256: "e".repeat(64) };
  return {
    input: { metadata, runtimeInputs },
    cell: { id: "N7" },
    source: {
      n: record.sourceN,
      requestId: record.requestId,
      method: "Pull",
      transport: "grpc",
      reply: {
        ok: true,
        unknown: false,
        status: 200,
        bodyBytes: sourceBody.length,
        bodySha256: hash(sourceBody),
      },
    },
    sourceBody,
    actual: undefined,
    localBody: undefined,
    disposition: {
      owner1209: {
        proposalSha256: "71bd68a98cc6914915719dc499c616be2ecf518b18e71c51b5add7e3c16920d4",
      },
      owner1210: {
        rowSha256WithLf: "d15612429b4ac1c5f88d5c1b020cedc0bce13f331aa7a85b20e89e4a3ac3d004",
      },
      proofIndexSha256: "7e5f79100f723fb033057b77c2798c754dbda713f40948dabea58b9793579e36",
      source: { ...metadata },
      runtimeInputs: { ...runtimeInputs },
      cells: ["N7"],
    },
  };
}
test(
  "C N7 second pair remains unqualified until genuine final local raw exists",
  { skip: !secondFixturePath },
  () => {
    assert.equal(secondFixtures.length, 2);
    for (const record of secondFixtures) {
      assert.equal(record.localObserved, false);
      const f = secondSourceFixture(record);
      const p = compareEmptyAttributeValueDisposition(f);
      assert.equal(p.verdict, "NOT_COMPARABLE");
      assert.match(p.reason, /raw body pins required/);
      assert.equal(p.owner, 1210);
      assert.equal(f.localBody, undefined);
      assert.equal(f.actual, undefined);
    }
  },
);
test(
  "C N7 second pair requires separate owner and exact source coordinates",
  { skip: !secondFixturePath },
  async (t) => {
    const cases = [
      [
        "first owner alone",
        (f) => delete f.disposition.owner1210,
        "NOT_COMPARABLE",
        /binding unavailable/,
      ],
      [
        "wrong second owner",
        (f) => (f.disposition.owner1210.rowSha256WithLf = "f".repeat(64)),
        "NOT_COMPARABLE",
        /binding unavailable/,
      ],
      [
        "wrong proof index",
        (f) =>
          (f.disposition.proofIndexSha256 =
            "5af9b45bce6882fb869b37dd721c9ae57908b14964909ee9793dc8515ef8c31d"),
        "NOT_COMPARABLE",
        /binding unavailable/,
      ],
      [
        "wrong source binding",
        (f) => (f.disposition.source.runId = "567e1cd860a1"),
        "NOT_COMPARABLE",
        /binding unavailable/,
      ],
      [
        "wrong runtime",
        (f) => (f.disposition.runtimeInputs.inputsSha256 = "f".repeat(64)),
        "NOT_COMPARABLE",
        /binding unavailable/,
      ],
      ["other dispatch", (f) => f.source.n++, null],
      ["other request", (f) => f.source.requestId++, null],
      ["other run", (f) => (f.input.metadata.runId = "other"), null],
      [
        "first-run coordinates",
        (f) => {
          f.source.n = 971;
          f.source.requestId = 386;
        },
        null,
      ],
    ];
    for (const [name, mutate, expected, reason] of cases)
      await t.test(name, () => {
        const f = secondSourceFixture(secondFixtures[0]);
        mutate(f);
        const p = compareEmptyAttributeValueDisposition(f);
        assert.equal(p?.verdict ?? null, expected);
        if (reason) assert.match(p.reason, reason);
      });
  },
);
