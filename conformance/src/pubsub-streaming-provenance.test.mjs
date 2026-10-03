import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";

const target = new URL("../pubsub-corpus/streaming-provenance.mjs", import.meta.url);
const limits = { maxRows: 32, maxHeaderPairs: 8, maxHeaderBytes: 4096, maxMessageBytes: 64 };
async function reducer() {
  assert.ok(existsSync(target), "pure streaming provenance reducer is missing");
  return (await import(target.href)).reduceStreamingProvenance;
}
const terminal = (seq = 2, extra = {}) => ({
  kind: "trailers",
  seq,
  committed: true,
  flags: 0,
  rawHeaders: ["grpc-status", "0"],
  ...extra,
});
const stop = (seq = 3, cause = "client-cancel") => ({
  kind: "local-stop-entry",
  seq,
  committed: true,
  cause,
});
const half = (seq = 1) => ({ kind: "half-close-entry", seq, committed: true });
const data = (seq = 3, bodyBytes = 0) => ({ kind: "data", seq, committed: true, bodyBytes });
const marker = (seq, event) => ({ kind: "marker", seq, committed: true, event });
const uncertain = (result, reason) => {
  assert.equal(result.verdict, "uncertain");
  assert.ok(result.reasons.includes(reason), `missing reason ${reason}: ${JSON.stringify(result)}`);
  assert.equal(new Set(result.reasons).size, result.reasons.length);
};

test("durable_trailers_and_trailers_only_responses_are_the_only_peer_terminals", async () => {
  const reduce = await reducer();
  for (let status = 0; status <= 16; status++) {
    for (const [kind, flags] of [
      ["trailers", 0],
      ["trailers", 255],
      ["response", 1],
      ["response", 129],
    ]) {
      const result = reduce(
        [terminal(2, { kind, flags, rawHeaders: ["grpc-status", String(status)] })],
        limits,
      );
      assert.deepEqual(result, {
        localCause: null,
        localCauseSeq: null,
        peerTerminal: { status, message: null, statusDetailsRaw: [] },
        peerTerminalSeq: 2,
        verdict: "peer-terminal",
        reasons: [],
      });
    }
    assert.equal(
      reduce([terminal(2, { rawHeaders: ["grpc-status", `000${status}`] })], limits).peerTerminal
        .status,
      status,
    );
  }
  for (const row of [
    terminal(1, { kind: "response", flags: 0 }),
    terminal(1, { kind: "additional", flags: 1 }),
  ]) {
    const result = reduce([row], limits);
    uncertain(result, "missing-peer-terminal");
    assert.equal(result.peerTerminal, null);
  }
});

test("terminal_metadata_keeps_order_duplicates_and_raw_details", async () => {
  const reduce = await reducer();
  for (const value of ["0", "7"]) {
    uncertain(
      reduce(
        [terminal(1, { rawHeaders: ["grpc-status", "0", "other", "x", "grpc-status", value] })],
        limits,
      ),
      "duplicate-status",
    );
  }
  uncertain(
    reduce(
      [terminal(1, { rawHeaders: ["grpc-status", "0", "grpc-message", "a", "grpc-message", "a"] })],
      limits,
    ),
    "duplicate-message",
  );
  const rows = [
    terminal(1, {
      rawHeaders: [
        "GRPC-STATUS",
        "0",
        "grpc-status-details-bin",
        "raw%notBase64",
        "grpc-message",
        "",
        "grpc-status-details-bin",
        "",
      ],
    }),
  ];
  const snapshot = structuredClone(rows);
  const result = reduce(rows, limits);
  assert.equal(result.verdict, "peer-terminal");
  assert.deepEqual(result.peerTerminal, {
    status: 0,
    message: "",
    statusDetailsRaw: ["raw%notBase64", ""],
  });
  result.peerTerminal.statusDetailsRaw.push("detached");
  assert.deepEqual(rows, snapshot);
});

test("missing_malformed_and_out_of_range_status_is_uncertain", async () => {
  const reduce = await reducer();
  uncertain(reduce([terminal(1, { rawHeaders: [] })], limits), "missing-status");
  for (const status of [
    "",
    "-0",
    "+0",
    " 0",
    "0 ",
    "0.0",
    "NaN",
    "Infinity",
    "0x0",
    "17",
    "99999999999999999999",
    "０",
    "0\n",
  ]) {
    const result = reduce([terminal(1, { rawHeaders: ["grpc-status", status] })], limits);
    uncertain(result, "invalid-status");
    assert.equal(result.peerTerminal, null);
  }
  for (const status of [0, null, {}, true])
    uncertain(
      reduce([terminal(1, { rawHeaders: ["grpc-status", status] })], limits),
      "invalid-headers",
    );
});

test("messages_decode_percent_escapes_within_the_bound", async () => {
  const reduce = await reducer();
  for (const [raw, decoded] of [
    ["", ""],
    ["a+b%20c", "a+b c"],
    ["%E6%97%A5%E6%9C%AC", "日本"],
    ["x%00y", "x\0y"],
    ["é%21", "é!"],
  ]) {
    const result = reduce(
      [terminal(1, { rawHeaders: ["grpc-status", "0", "grpc-message", raw] })],
      { ...limits, maxMessageBytes: Math.max(1, Buffer.byteLength(decoded)) },
    );
    assert.equal(result.verdict, "peer-terminal");
    assert.equal(result.peerTerminal.message, decoded);
  }
  for (const raw of [
    "%",
    "%0",
    "%GG",
    "%FF",
    "%C0%AF",
    "%ED%A0%80",
    "%E2%82",
    "\ud800",
    "\udc00",
  ]) {
    uncertain(
      reduce([terminal(1, { rawHeaders: ["grpc-status", "0", "grpc-message", raw] })], limits),
      "invalid-message",
    );
  }
  uncertain(
    reduce([terminal(1, { rawHeaders: ["grpc-status", "0", "grpc-message", "%C3%A9"] })], {
      ...limits,
      maxMessageBytes: 1,
    }),
    "message-byte-limit",
  );
});

test("a_second_terminal_or_data_after_end_stream_stays_uncertain", async () => {
  const reduce = await reducer();
  for (const second of [
    terminal(3),
    terminal(3, { rawHeaders: [] }),
    terminal(3, { committed: false }),
  ]) {
    const result = reduce([terminal(1), stop(2), second], limits);
    uncertain(result, "second-terminal");
    assert.equal(result.peerTerminalSeq, 1);
  }
  for (const boundary of [
    terminal(1),
    terminal(1, { kind: "response", flags: 1 }),
    terminal(1, { rawHeaders: [] }),
    terminal(1, { committed: false }),
  ]) {
    for (const bytes of [0, 1])
      uncertain(reduce([boundary, stop(2), data(3, bytes)], limits), "data-after-terminal");
  }
  assert.equal(
    reduce([data(1), terminal(2), marker(3, "peer-end")], limits).verdict,
    "peer-terminal",
  );
});

test("an_uncommitted_terminal_never_acquires_peer_authority", async () => {
  const reduce = await reducer();
  const result = reduce([terminal(1, { committed: false }), terminal(2)], limits);
  uncertain(result, "uncommitted-terminal");
  assert.equal(result.peerTerminalSeq, 2);
  assert.equal(reduce([terminal(1, { committed: false })], limits).peerTerminal, null);
});

test("peer_terminal_before_local_stop_preserves_both_causes", async () => {
  const reduce = await reducer();
  for (const cause of [
    "client-cancel",
    "abort",
    "deadline",
    "close",
    "reset",
    "revocation",
    "uncertain",
  ]) {
    const result = reduce([stop(3, cause), terminal(2), stop(4, "reset")], limits);
    assert.deepEqual(result, {
      localCause: cause,
      localCauseSeq: 3,
      peerTerminal: { status: 0, message: null, statusDetailsRaw: [] },
      peerTerminalSeq: 2,
      verdict: "peer-terminal",
      reasons: [],
    });
  }
});

test("peer_terminal_after_local_stop_is_uncertain", async () => {
  const reduce = await reducer();
  const result = reduce([terminal(2), marker(3, "local-stop-return"), stop(1)], limits);
  uncertain(result, "peer-after-local-stop");
  assert.equal(result.peerTerminalSeq, 2);
  assert.equal(result.localCauseSeq, 1);
  assert.equal(
    reduce([terminal(1), marker(2, "local-stop-return")], limits).verdict,
    "peer-terminal",
  );
});

test("local_lifecycle_never_fabricates_a_peer_status", async () => {
  const reduce = await reducer();
  for (const cause of [
    "client-cancel",
    "abort",
    "deadline",
    "close",
    "reset",
    "revocation",
    "uncertain",
  ]) {
    const result = reduce([stop(1, cause)], limits);
    assert.equal(result.verdict, "local-stop");
    assert.equal(result.peerTerminal, null);
  }
  assert.equal(reduce([{ ...stop(1), committed: false }], limits).verdict, "local-stop");
  for (const event of [
    "issue-entry",
    "issue-return",
    "peer-end",
    "peer-close",
    "peer-error",
    "peer-reset",
    "peer-goaway",
    "local-stop-return",
    "native-close-ack",
  ]) {
    const result = reduce([marker(1, event)], limits);
    uncertain(result, "missing-peer-terminal");
    assert.equal(result.peerTerminal, null);
  }
});

test("half_close_is_distinct_from_an_actual_local_stop", async () => {
  const reduce = await reducer();
  const alone = reduce([half()], limits);
  assert.equal(alone.localCause, "half-close");
  assert.equal(alone.peerTerminal, null);
  uncertain(alone, "missing-peer-terminal");
  assert.equal(reduce([half(1), terminal(2)], limits).verdict, "peer-terminal");
  const result = reduce([half(0), stop(1, "deadline"), terminal(2)], limits);
  uncertain(result, "peer-after-local-stop");
  assert.equal(result.localCause, "deadline");
  assert.equal(result.localCauseSeq, 1);
  assert.equal(reduce([half(0), terminal(1), stop(2)], limits).verdict, "peer-terminal");
});

function permutations(items) {
  if (items.length < 2) return [items];
  return items.flatMap((item, i) =>
    permutations(items.filter((_, j) => i !== j)).map((tail) => [item].concat(tail)),
  );
}
test("native_sequences_determine_causality_not_storage_order", async () => {
  const reduce = await reducer();
  for (const rows of [
    [half(0), data(1), terminal(2), stop(4)],
    [stop(0), terminal(2), marker(5, "local-stop-return")],
    [terminal(0), data(2), terminal(4)],
  ]) {
    const expected = reduce(rows, limits);
    for (const storage of permutations(rows)) assert.deepEqual(reduce(storage, limits), expected);
  }
  assert.equal(reduce([stop(0), terminal(Number.MAX_SAFE_INTEGER)], limits).verdict, "uncertain");
});

test("invalid_sequences_and_unknown_rows_fail_closed", async () => {
  const reduce = await reducer();
  for (const seq of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity, "1", null])
    uncertain(reduce([terminal(seq)], limits), "invalid-sequence");
  for (const rows of [
    [terminal(1), terminal(1)],
    [terminal(1), stop(1)],
  ])
    uncertain(reduce(rows, limits), "duplicate-sequence");
  for (const flags of [-1, 256, 1.5, "1", NaN])
    uncertain(reduce([terminal(1, { flags })], limits), "invalid-flags");
  for (const rawHeaders of [["grpc-status"], null, {}, ["grpc-status", "0", "x", false]])
    uncertain(reduce([terminal(1, { rawHeaders })], limits), "invalid-headers");
  for (const row of [null, [], {}, terminal(1, { committed: "true" }), terminal(1, { index: 99 })])
    uncertain(reduce([row], limits), "invalid-row");
  uncertain(reduce([terminal(1, { kind: "invented" })], limits), "unknown-kind");
  uncertain(reduce([stop(1, "half-close")], limits), "invalid-cause");
  uncertain(reduce([marker(1, "aborted")], limits), "unknown-event");
  uncertain(reduce(null, limits), "invalid-rows");
  for (const bodyBytes of [-1, 1.1, Number.MAX_SAFE_INTEGER + 1, "0"])
    uncertain(reduce([data(1, bodyBytes)], limits), "invalid-row");
  for (const bodyBytes of [0, Number.MAX_SAFE_INTEGER, undefined])
    assert.equal(reduce([data(1, bodyBytes), terminal(2)], limits).verdict, "peer-terminal");
  const accessor = terminal();
  Object.defineProperty(accessor, "flags", {
    get() {
      throw new Error("evidence getter must not run");
    },
    enumerable: true,
  });
  uncertain(reduce([accessor], limits), "invalid-row");
  const hiddenAccessor = terminal();
  Object.defineProperty(hiddenAccessor, "flags", {
    get() {
      throw new Error("hidden getter must not run");
    },
    enumerable: false,
  });
  uncertain(reduce([hiddenAccessor], limits), "invalid-row");
  const headerAccessor = terminal();
  Object.defineProperty(headerAccessor.rawHeaders, 1, {
    get() {
      throw new Error("raw pair getter must not run");
    },
    enumerable: true,
  });
  uncertain(reduce([headerAccessor], limits), "invalid-headers");
  const rowAccessor = [terminal()];
  Object.defineProperty(rowAccessor, 0, {
    get() {
      throw new Error("row array getter must not run");
    },
    enumerable: true,
  });
  uncertain(reduce(rowAccessor, limits), "invalid-row");
});

test("evidence_bounds_refuse_before_unbounded_processing", async () => {
  const reduce = await reducer();
  assert.equal(reduce([terminal(1)], { ...limits, maxRows: 1 }).verdict, "peer-terminal");
  uncertain(reduce([terminal(1), stop(2)], { ...limits, maxRows: 1 }), "row-limit");
  assert.equal(reduce([terminal(1)], { ...limits, maxHeaderPairs: 1 }).verdict, "peer-terminal");
  uncertain(
    reduce([terminal(1, { rawHeaders: ["grpc-status", "0", "x", "y"] })], {
      ...limits,
      maxHeaderPairs: 1,
    }),
    "header-pair-limit",
  );
  assert.equal(reduce([terminal(1)], { ...limits, maxHeaderBytes: 12 }).verdict, "peer-terminal");
  uncertain(reduce([terminal(1)], { ...limits, maxHeaderBytes: 11 }), "header-byte-limit");
  uncertain(
    reduce([terminal(1, { kind: "additional" }), terminal(2)], { ...limits, maxHeaderBytes: 23 }),
    "header-byte-limit",
  );
  assert.equal(
    reduce([terminal(1, { rawHeaders: ["grpc-status", "0", "x", "é"] })], {
      ...limits,
      maxHeaderBytes: 15,
    }).verdict,
    "peer-terminal",
  );
  uncertain(
    reduce([terminal(1, { rawHeaders: ["grpc-status", "0", "x", "é"] })], {
      ...limits,
      maxHeaderBytes: 14,
    }),
    "header-byte-limit",
  );
  uncertain(
    reduce([terminal(1, { rawHeaders: ["grpc-status", "0".repeat(4096)] })], limits),
    "header-byte-limit",
  );
  assert.equal(
    reduce([terminal(1, { rawHeaders: ["grpc-status", "0".repeat(4085)] })], limits).verdict,
    "peer-terminal",
  );
  const oversizedSuffix = reduce(
    [terminal(0), terminal(1, { kind: "additional", rawHeaders: ["x", "a".repeat(4096)] })],
    limits,
  );
  uncertain(oversizedSuffix, "header-byte-limit");
  assert.equal(
    oversizedSuffix.peerTerminal,
    null,
    "an admitted prefix cannot bypass complete byte admission",
  );
  const atMessageCap = terminal(1, {
    rawHeaders: ["grpc-status", "0", "grpc-message", "a".repeat(64)],
  });
  assert.equal(reduce([atMessageCap], limits).verdict, "peer-terminal");
  uncertain(
    reduce(
      [terminal(1, { rawHeaders: ["grpc-status", "0", "grpc-message", "a".repeat(65)] })],
      limits,
    ),
    "message-byte-limit",
  );
  for (const key of Object.keys(limits))
    for (const value of [undefined, 0, -1, 1.5, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1]) {
      assert.throws(() => reduce([], { ...limits, [key]: value }), /positive safe integer/);
    }
  assert.throws(() => reduce([]), /bounds/);
  const headerGetter = terminal(1);
  Object.defineProperty(headerGetter, "rawHeaders", {
    get() {
      throw new Error("row cap must precede metadata");
    },
    enumerable: true,
  });
  uncertain(reduce([terminal(0), headerGetter], { ...limits, maxRows: 1 }), "row-limit");
  const pairGetter = terminal(1, { rawHeaders: ["grpc-status", "0", "x", "y"] });
  Object.defineProperty(pairGetter.rawHeaders, 3, {
    get() {
      throw new Error("pair cap must precede pair values");
    },
    enumerable: true,
  });
  uncertain(reduce([pairGetter], { ...limits, maxHeaderPairs: 1 }), "header-pair-limit");
});

test("all_own_fields_are_closed_data_descriptors_regardless_of_enumerability", async () => {
  const reduce = await reducer();
  for (const field of ["index", "journalIndex", "other", "toString", "__proto__"]) {
    for (const enumerable of [false, true]) {
      for (const accessor of [false, true]) {
        const row = terminal(1);
        let calls = 0;
        Object.defineProperty(
          row,
          field,
          accessor
            ? {
                get() {
                  calls++;
                  throw new Error("unknown getter must not run");
                },
                enumerable,
              }
            : { value: 99, enumerable },
        );
        const result = reduce([row], limits);
        uncertain(result, "invalid-row");
        assert.equal(result.peerTerminal, null);
        assert.equal(calls, 0);
      }
    }
  }
  for (const row of [terminal(1), stop(1), marker(1, "peer-reset"), data(1)]) {
    for (const field of Object.getOwnPropertyNames(row)) {
      let calls = 0;
      const input = { ...row };
      Object.defineProperty(input, field, {
        get() {
          calls++;
          throw new Error("known hidden getter must not run");
        },
        enumerable: false,
      });
      uncertain(reduce([input], limits), "invalid-row");
      assert.equal(calls, 0);
    }
  }
  const hiddenData = {};
  for (const [field, value] of Object.entries(terminal(1))) {
    Object.defineProperty(hiddenData, field, { value, enumerable: false });
  }
  assert.deepEqual(reduce([hiddenData], limits), reduce([terminal(1)], limits));
  const symbolRow = terminal(1);
  Object.defineProperty(symbolRow, Symbol("hidden"), { value: 99, enumerable: false });
  uncertain(reduce([symbolRow], limits), "invalid-row");
});

test("the_result_is_pure_deterministic_and_detached", async () => {
  const reduce = await reducer();
  const rows = [
    terminal(1, { rawHeaders: ["grpc-status", "0", "grpc-status-details-bin", "abc"] }),
    stop(2),
  ];
  rows.forEach((row) => {
    if (row.rawHeaders) Object.freeze(row.rawHeaders);
    Object.freeze(row);
  });
  Object.freeze(rows);
  const a = reduce(rows, limits);
  const b = reduce(rows, limits);
  assert.deepEqual(a, b);
  assert.notEqual(a, b);
  assert.notEqual(a.reasons, b.reasons);
  assert.notEqual(a.peerTerminal, b.peerTerminal);
  assert.notEqual(a.peerTerminal.statusDetailsRaw, b.peerTerminal.statusDetailsRaw);
  assert.deepEqual(
    Object.keys(a).toSorted(),
    [
      "localCause",
      "localCauseSeq",
      "peerTerminal",
      "peerTerminalSeq",
      "verdict",
      "reasons",
    ].toSorted(),
  );
});

// This oracle joins independent facts by sets and minima; it does not sort or scan chronology.
// Its metadata decoder builds UTF-8 bytes explicitly rather than using decodeURIComponent.
function reference(rows, bounds = limits) {
  const reasons = new Set();
  const finish = (local = null, peer = null) => ({
    localCause: local?.cause ?? null,
    localCauseSeq: local?.seq ?? null,
    peerTerminal: peer?.value ?? null,
    peerTerminalSeq: peer?.seq ?? null,
    verdict: reasons.size ? "uncertain" : peer ? "peer-terminal" : "local-stop",
    reasons: [...reasons].toSorted(),
  });
  if (!Array.isArray(rows)) {
    reasons.add("invalid-rows");
    return finish();
  }
  if (rows.length > bounds.maxRows) {
    reasons.add("row-limit");
    return finish();
  }
  const schemas = {
    response: ["flags", "rawHeaders"],
    trailers: ["flags", "rawHeaders"],
    additional: ["flags", "rawHeaders"],
    data: ["bodyBytes"],
    "local-stop-entry": ["cause"],
    "half-close-entry": [],
    marker: ["event"],
  };
  const causes = new Set([
    "client-cancel",
    "abort",
    "deadline",
    "close",
    "reset",
    "revocation",
    "uncertain",
  ]);
  const events = new Set([
    "issue-entry",
    "issue-return",
    "peer-end",
    "peer-close",
    "peer-error",
    "peer-reset",
    "peer-goaway",
    "local-stop-return",
    "native-close-ack",
  ]);
  const eligible = [];
  const ids = new Map();
  let bytes = 0;
  for (const row of rows) {
    if (!row || Array.isArray(row) || typeof row !== "object") {
      reasons.add("invalid-row");
      continue;
    }
    const names = Object.getOwnPropertyNames(row);
    const descriptors = Object.getOwnPropertyDescriptors(row);
    if (
      Object.getOwnPropertySymbols(row).length ||
      names.some((name) => !("value" in descriptors[name]))
    ) {
      reasons.add("invalid-row");
      continue;
    }
    if (typeof row.committed !== "boolean" || typeof row.kind !== "string") {
      reasons.add("invalid-row");
      continue;
    }
    if (!(row.kind in schemas)) {
      reasons.add("unknown-kind");
      continue;
    }
    if (names.some((key) => !["kind", "seq", "committed", ...schemas[row.kind]].includes(key))) {
      reasons.add("invalid-row");
      continue;
    }
    if (!Number.isSafeInteger(row.seq) || row.seq < 0) {
      reasons.add("invalid-sequence");
      continue;
    }
    ids.set(row.seq, (ids.get(row.seq) ?? 0) + 1);
    let good = true;
    if (["response", "trailers", "additional"].includes(row.kind)) {
      if (!Number.isInteger(row.flags) || row.flags < 0 || row.flags > 255) {
        reasons.add("invalid-flags");
        good = false;
      }
      if (!Array.isArray(row.rawHeaders) || row.rawHeaders.length % 2) {
        reasons.add("invalid-headers");
        good = false;
      } else {
        if (row.rawHeaders.length / 2 > bounds.maxHeaderPairs) {
          reasons.add("header-pair-limit");
          return finish();
        }
        if (row.rawHeaders.some((value) => typeof value !== "string")) {
          reasons.add("invalid-headers");
          good = false;
        } else
          for (const value of row.rawHeaders) {
            bytes += Buffer.byteLength(value);
            if (bytes > bounds.maxHeaderBytes) {
              reasons.add("header-byte-limit");
              return finish();
            }
          }
      }
    }
    if (row.kind === "local-stop-entry" && !causes.has(row.cause)) {
      reasons.add("invalid-cause");
      good = false;
    }
    if (row.kind === "marker" && !events.has(row.event)) {
      reasons.add("unknown-event");
      good = false;
    }
    if (
      row.kind === "data" &&
      row.bodyBytes !== undefined &&
      (!Number.isSafeInteger(row.bodyBytes) || row.bodyBytes < 0)
    ) {
      reasons.add("invalid-row");
      good = false;
    }
    if (good) eligible.push(row);
  }
  const repeated = new Set([...ids].filter(([, count]) => count > 1).map(([id]) => id));
  if (repeated.size) reasons.add("duplicate-sequence");
  const facts = eligible.filter((row) => !repeated.has(row.seq));
  const minimum = (entries) =>
    entries.reduce((best, item) => (!best || item.seq < best.seq ? item : best), null);
  const actual = minimum(facts.filter((row) => row.kind === "local-stop-entry"));
  const halfClose = minimum(facts.filter((row) => row.kind === "half-close-entry"));
  const local = actual || (halfClose ? { ...halfClose, cause: "half-close" } : null);
  const terminals = facts.filter(
    (row) => row.kind === "trailers" || (row.kind === "response" && row.flags % 2 === 1),
  );
  if (terminals.length > 1) reasons.add("second-terminal");
  if (facts.some((row) => row.kind === "data" && terminals.some((end) => end.seq < row.seq)))
    reasons.add("data-after-terminal");
  const peers = [];
  for (const row of terminals) {
    if (actual && actual.seq < row.seq) reasons.add("peer-after-local-stop");
    const pairs = Array.from({ length: row.rawHeaders.length / 2 }, (_, i) => [
      row.rawHeaders[2 * i].toLowerCase(),
      row.rawHeaders[2 * i + 1],
    ]);
    const statuses = pairs.filter(([key]) => key === "grpc-status").map(([, value]) => value);
    const messages = pairs.filter(([key]) => key === "grpc-message").map(([, value]) => value);
    const invalid = new Set();
    if (!row.committed) invalid.add("uncommitted-terminal");
    if (!statuses.length) invalid.add("missing-status");
    if (statuses.length > 1) invalid.add("duplicate-status");
    const digits = statuses.length === 1 ? [...statuses[0]] : [];
    const status = digits.reduce(
      (sum, char) => Math.min(17, sum * 10 + char.charCodeAt(0) - 48),
      0,
    );
    if (
      statuses.length === 1 &&
      (!digits.length || digits.some((char) => char < "0" || char > "9") || status > 16)
    )
      invalid.add("invalid-status");
    if (messages.length > 1) invalid.add("duplicate-message");
    let message = null;
    if (messages.length === 1) {
      try {
        const raw = messages[0];
        const wire = [];
        for (let i = 0; i < raw.length;) {
          if (raw[i] === "%") {
            const code = raw.slice(i + 1, i + 3);
            if (code.length !== 2 || [...code].some((c) => !"0123456789abcdefABCDEF".includes(c)))
              throw new Error("bad escape");
            wire.push(Number.parseInt(code, 16));
            i += 3;
          } else {
            const point = raw.codePointAt(i);
            if (point >= 0xd800 && point <= 0xdfff) throw new Error("bad surrogate");
            const char = String.fromCodePoint(point);
            wire.push(...Buffer.from(char));
            i += char.length;
          }
        }
        message = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
          Uint8Array.from(wire),
        );
        if (wire.length > bounds.maxMessageBytes) invalid.add("message-byte-limit");
      } catch {
        invalid.add("invalid-message");
      }
    }
    for (const reason of invalid) reasons.add(reason);
    if (!invalid.size)
      peers.push({
        seq: row.seq,
        value: {
          status,
          message,
          statusDetailsRaw: pairs
            .filter(([key]) => key === "grpc-status-details-bin")
            .map(([, value]) => value),
        },
      });
  }
  const peer = minimum(peers);
  if (!terminals.length && !actual) reasons.add("missing-peer-terminal");
  return finish(local, peer);
}

test("generated_chronologies_match_an_independent_oracle_and_reach_every_class", async () => {
  const reduce = await reducer();
  const reached = new Set();
  const verdicts = new Set();
  const check = (rows, bounds = limits) => {
    const actual = reduce(rows, bounds);
    assert.deepEqual(actual, reference(rows, bounds), "independent provenance model mismatch");
    actual.reasons.forEach((reason) => reached.add(reason));
    verdicts.add(actual.verdict);
  };
  const negativeCases = [
    [null],
    [[terminal(0), stop(1)], { ...limits, maxRows: 1 }],
    [[null]],
    [[terminal(-1)]],
    [[terminal(0), terminal(0)]],
    [[terminal(0, { flags: -1 })]],
    [[terminal(0, { rawHeaders: ["x"] })]],
    [[terminal(0)], { ...limits, maxHeaderPairs: 1, maxHeaderBytes: 11 }],
    [
      [terminal(0, { rawHeaders: ["grpc-status", "0", "x", "y"] })],
      { ...limits, maxHeaderPairs: 1 },
    ],
    [[terminal(0, { kind: "unknown" })]],
    [[stop(0, "half-close")]],
    [[marker(0, "unknown")]],
    [[terminal(0, { committed: false })]],
    [[terminal(0, { rawHeaders: [] })]],
    [[terminal(0, { rawHeaders: ["grpc-status", "0", "grpc-status", "0"] })]],
    [[terminal(0, { rawHeaders: ["grpc-status", "17"] })]],
    [[terminal(0, { rawHeaders: ["grpc-status", "0", "grpc-message", "a", "grpc-message", "a"] })]],
    [[terminal(0, { rawHeaders: ["grpc-status", "0", "grpc-message", "%FF"] })]],
    [
      [terminal(0, { rawHeaders: ["grpc-status", "0", "grpc-message", "aa"] })],
      { ...limits, maxMessageBytes: 1 },
    ],
    [[terminal(0), terminal(1)]],
    [[terminal(0), data(1)]],
    [[stop(0), terminal(1)]],
    [[]],
  ];
  for (const [rows, bounds] of negativeCases) check(rows, bounds ?? limits);
  for (const field of ["index", "nativeSequence", "other"]) {
    for (const enumerable of [false, true]) {
      const hiddenUnknown = terminal(0);
      Object.defineProperty(hiddenUnknown, field, { value: 99, enumerable });
      check([hiddenUnknown]);
      const hiddenAccessor = terminal(0);
      let calls = 0;
      Object.defineProperty(hiddenAccessor, field, {
        get() {
          calls++;
          return 99;
        },
        enumerable,
      });
      check([hiddenAccessor]);
      assert.equal(calls, 0);
    }
  }
  for (const field of Object.getOwnPropertyNames(terminal(0))) {
    const hiddenKnown = terminal(0);
    let calls = 0;
    Object.defineProperty(hiddenKnown, field, {
      get() {
        calls++;
        return 0;
      },
      enumerable: false,
    });
    check([hiddenKnown]);
    assert.equal(calls, 0);
  }
  const hiddenKnownData = {};
  for (const [field, value] of Object.entries(terminal(0)))
    Object.defineProperty(hiddenKnownData, field, { value, enumerable: false });
  check([hiddenKnownData]);
  let state = 0x4b1d5e77;
  const random = (n) => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) % n;
  };
  for (let i = 0; i < 1500; i++) {
    const rows = [];
    for (let seq = 0, count = random(7); seq < count; seq++) {
      switch (random(8)) {
        case 0:
          rows.push(stop(seq, ["client-cancel", "deadline", "reset"][random(3)]));
          break;
        case 1:
          rows.push(half(seq));
          break;
        case 2:
          rows.push(data(seq, random(2)));
          break;
        case 3:
          rows.push(marker(seq, ["peer-reset", "peer-goaway", "peer-end"][random(3)]));
          break;
        default: {
          const shape = random(8);
          const headers = ["grpc-status", String(random(18))];
          if (shape === 0) headers.length = 0;
          if (shape === 1) headers.push("grpc-status", headers[1]);
          if (shape === 2) headers[1] = " 0";
          if (shape === 3) headers.push("grpc-message", "%E6%97%A5+a");
          if (shape === 4) headers.push("grpc-message", "%FF");
          if (shape === 5)
            headers.push("grpc-status-details-bin", "abc", "grpc-status-details-bin", "def");
          rows.push(
            terminal(seq, {
              kind: ["trailers", "response", "additional"][random(3)],
              flags: random(2),
              committed: random(4) !== 0,
              rawHeaders: headers,
            }),
          );
        }
      }
    }
    check(rows);
    for (let j = rows.length - 1; j > 0; j--) {
      const k = random(j + 1);
      [rows[j], rows[k]] = [rows[k], rows[j]];
    }
    check(rows);
  }
  assert.deepEqual([...verdicts].toSorted(), ["local-stop", "peer-terminal", "uncertain"]);
  assert.deepEqual(
    [...reached].toSorted(),
    [
      "invalid-rows",
      "row-limit",
      "invalid-row",
      "invalid-sequence",
      "duplicate-sequence",
      "invalid-flags",
      "invalid-headers",
      "header-pair-limit",
      "header-byte-limit",
      "unknown-kind",
      "invalid-cause",
      "unknown-event",
      "uncommitted-terminal",
      "missing-status",
      "duplicate-status",
      "invalid-status",
      "duplicate-message",
      "invalid-message",
      "message-byte-limit",
      "second-terminal",
      "data-after-terminal",
      "peer-after-local-stop",
      "missing-peer-terminal",
    ].toSorted(),
  );
});
