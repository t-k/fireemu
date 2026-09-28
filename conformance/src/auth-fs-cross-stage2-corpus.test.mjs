import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  HELD,
  STAGE2_CONDITIONS,
  STAGE2_PRINCIPALS,
  STAGE2_PROGRAM,
} from "./auth-fs-cross/programs-stage2.mjs";
import { closureTransports, validateStage2 } from "./auth-fs-cross/stage2-corpus.mjs";
import { RULESET_IDS, rulesetSource } from "./auth-fs-cross/stage2-rulesets.mjs";

const closure = closureTransports(
  JSON.parse(
    readFileSync(
      new URL("../../spec/compatibility/closure/AUTH-FS-CROSS.json", import.meta.url),
      "utf8",
    ),
  ),
);
const copy = () => structuredClone(STAGE2_PROGRAM);
const validate = (program) => validateStage2(program, { closure });
const indexOf = (program, match) => program.steps.findIndex(match);

test("the stage-2 program passes its guard and covers every closure transport", () => {
  assert.deepEqual(Object.keys(closure).toSorted(), [...STAGE2_CONDITIONS].toSorted());
  assert.deepEqual(validate(STAGE2_PROGRAM), {
    commits: 43,
    reads: 15,
    rows: 56,
    maxWire: 2_200,
    maxConnections: 380,
  });
});

test("every held principal's change comes after the short conditions and before its probes", () => {
  const steps = STAGE2_PROGRAM.steps;
  const lastShort = steps.findLastIndex((s) => s.do === "close-client");
  const changes = HELD.filter((h) => h.change).map((h) => steps.indexOf(h.change));
  const afterChange = indexOf(STAGE2_PROGRAM, (s) => s.id === "held/after-change");
  for (const at of changes) assert.ok(at > lastShort && at < afterChange);
  const expiry = steps
    .flatMap((s) => (s.do === "expiry-groups" ? s.groups : s.do === "expiry-probes" ? [s] : []))
    .map((g) => [g.id, g.plus, g.align ?? "own"]);
  assert.deepEqual(expiry, [
    ["held/exp-minus-60", -60, "own"],
    ["held/exp-plus-35-grpc", 35, "latest"],
    ["held/exp-plus-35-sdk", 35, "own"],
  ]);
  // The native tokens are refreshed right before the streams open, after every setup step.
  const firstStream = steps.findIndex((s) => s.do === "stream");
  assert.deepEqual(
    steps.slice(0, firstStream).map((s) => [s.action, s.principal]),
    HELD.map((h) => ["refresh", h.principal]),
  );
});

test("the program and the rules name only this lane's collections", () => {
  const text = JSON.stringify(STAGE2_PROGRAM);
  for (const [, collection] of text.matchAll(/"(?:doc|path|document|collection)":"([a-z0-9-]+)/g))
    assert.match(collection, /^afc2-/);
  for (const id of RULESET_IDS) {
    const source = rulesetSource(id);
    for (const [, collection] of source.matchAll(/match \/([a-z0-9-]+)\/\{/g))
      if (collection !== "databases") assert.match(collection, /^(afc2-|fsr-marker$)/);
  }
});

/** One change per case that the guard must refuse, with the message it must give. */
const REFUSED = [
  [
    "an unknown principal",
    (p) => (p.steps.find((s) => s.op === "signIn").as = "mallory"),
    /unknown principal mallory/,
  ],
  [
    "a principal of another provider",
    (p, principals) => (principals.alice = { provider: "password" }),
    /administrator-created/,
  ],
  [
    "a document outside the lane",
    (p) => (p.steps.find((s) => s.do === "probe").writes[0].doc = "users/x"),
    /not a document of this lane/,
  ],
  [
    "a climbing seed path",
    (p) => (p.seed[0].doc = "afc2-owned/../x"),
    /not a document of this lane/,
  ],
  [
    "a stream on another collection",
    (p) => (p.steps.find((s) => s.do === "stream").targets[1].collection = "users"),
    /not a collection of this lane/,
  ],
  [
    "a listener observed before it listens",
    (p) => {
      const at = indexOf(p, (s) => s.op === "listen" && s.name === "own-again");
      p.steps.splice(at, 1);
    },
    /listener n-out\/own-again does not exist/,
  ],
  [
    "a client used after it closed",
    (p) => {
      const at = indexOf(p, (s) => s.do === "close-client" && s.client === "n-claim");
      p.steps.splice(at + 1, 0, { do: "sdk", client: "n-claim", op: "signOut" });
    },
    /client n-claim is not open/,
  ],
  [
    "a principal signed in after its account is deleted",
    (p) =>
      p.steps.splice(
        p.steps.length - 1,
        0,
        { do: "client", client: "late", transport: "node-sdk", wireCap: 100, connectionCap: 10 },
        { do: "sdk", client: "late", op: "signIn", as: "del" },
      ),
    /principal del is used after its deletion/,
  ],
  [
    "a tenant principal signed in after its tenant is deleted",
    (p) =>
      p.steps.splice(
        p.steps.length - 1,
        0,
        { do: "client", client: "late", transport: "node-sdk", wireCap: 100, connectionCap: 10 },
        { do: "sdk", client: "late", op: "signIn", as: "ten-t1" },
      ),
    /tenant t1 is used after its deletion/,
  ],
  [
    "a duplicate row",
    (p) => (p.steps.find((s) => s.id === "claim/removed").id = "claim/added"),
    /duplicate row claim\/added/,
  ],
  [
    "an unknown condition",
    (p) => (p.steps.find((s) => s.id === "claim/added").condition = "X/y"),
    /unknown condition X\/y/,
  ],
  [
    "a condition without its browser rows",
    (p) => (p.steps = p.steps.filter((s) => !(s.client ?? s.id ?? "").startsWith("b-pend"))),
    /pending-write-across-switch: no row observes it through browser-webchannel/,
  ],
  [
    "a condition without its native rows",
    (p) => {
      for (const step of p.steps.filter((s) => s.do === "probe" || s.do === "expiry-probes")) {
        if (step.observe) step.observe = step.observe.filter((r) => !r.startsWith("grpc-"));
        for (const probe of step.probes ?? [])
          probe.observe = probe.observe.filter((r) => !r.startsWith("grpc-"));
        if (step.probes) step.probes = step.probes.filter((probe) => probe.observe.length);
      }
      const groups = p.steps.find((s) => s.do === "expiry-groups");
      groups.groups = groups.groups.filter((g) => !g.id.endsWith("-grpc"));
    },
    /listen-token-refresh: no row observes it through grpc/,
  ],
  [
    "a sleep past the limit",
    (p) => (p.steps.find((s) => s.do === "sleep").ms = 10 * 60_000),
    /out of range/,
  ],
  [
    "an expiry probe too far out",
    (p) => (p.steps.find((s) => s.do === "expiry-probes").plus = -3_600),
    /out of range/,
  ],
  [
    "a client without a connection cap",
    (p) => delete p.steps.find((s) => s.do === "client").connectionCap,
    /connection cap undefined out of range/,
  ],
  [
    "a connection cap past the limit",
    (p) => (p.steps.find((s) => s.do === "client").connectionCap = 101),
    /connection cap 101 out of range/,
  ],
  [
    "an owner's read naming an unknown client",
    (p) => (p.steps.find((s) => s.do === "server").client = "nobody"),
    /client nobody is not open/,
  ],
  [
    "an unknown alignment",
    (p) => (p.steps.find((s) => s.do === "expiry-groups").groups[0].align = "earliest"),
    /unknown alignment earliest/,
  ],
  [
    "an empty expiry group",
    (p) => (p.steps.find((s) => s.do === "expiry-groups").groups[1].probes = []),
    /an expiry group probes something/,
  ],
  [
    "no expiry groups",
    (p) => (p.steps.find((s) => s.do === "expiry-groups").groups = []),
    /at least one group/,
  ],
  [
    "a window past the limit",
    (p) => (p.steps.find((s) => s.do === "observe").windowMs = 120_000),
    /out of range/,
  ],
  [
    "an unknown op",
    (p) => (p.steps.find((s) => s.do === "sdk").op = "deleteUser"),
    /unknown op deleteUser/,
  ],
  [
    "an unknown action",
    (p) => (p.steps.find((s) => s.do === "auth").action = "delete-project"),
    /unknown action delete-project/,
  ],
  ["an unknown step", (p) => p.steps.splice(1, 0, { do: "fetch" }), /unknown step fetch/],
  [
    "a transaction the orchestrator would wait for",
    (p) => delete p.steps.find((s) => s.op === "transaction").await,
    /sent without waiting/,
  ],
  [
    "an await of an unknown command",
    (p) => (p.steps.find((s) => s.do === "await" && s.event === "result").commandId = "tx-x"),
    /unknown command tx-x/,
  ],
  [
    "an observation since an unknown mark",
    (p) => (p.steps.find((s) => s.do === "observe" && s.since).since = "nowhere"),
    /unknown mark nowhere/,
  ],
  [
    "a duplicate mark",
    (p) => (p.steps.find((s) => s.mark === "n-out/sign-out").mark = "claim/remove"),
    /duplicate mark/,
  ],
  [
    "close-all before the end",
    (p) => p.steps.push({ do: "sleep", ms: 1 }),
    /close-all ends the program/,
  ],
  ["a program without close-all", (p) => p.steps.pop(), /ends with close-all/],
  [
    "a second close-all in the middle",
    (p) => p.steps.splice(1, 0, { do: "close-all", id: "early", conditions: STAGE2_CONDITIONS }),
    /close-all ends the program/,
  ],
  [
    "a second client of one name",
    (p) =>
      p.steps.splice(1, 0, {
        do: "client",
        client: "sdk-rev",
        transport: "node-sdk",
        wireCap: 100,
        connectionCap: 10,
      }),
    /duplicate client sdk-rev/,
  ],
  [
    "an unknown transport",
    (p) => (p.steps.find((s) => s.do === "client").transport = "android"),
    /unknown transport android/,
  ],
  [
    "a client without a wire cap",
    (p) => delete p.steps.find((s) => s.do === "client").wireCap,
    /wire cap undefined out of range/,
  ],
  [
    "a wire cap past the limit",
    (p) => (p.steps.find((s) => s.do === "client").wireCap = 301),
    /wire cap 301 out of range/,
  ],
  ["an unknown ruleset", (p) => (p.ruleset = "cross"), /unknown ruleset cross/],
  ["an unknown tenant slot", (p) => p.tenants.push("t9"), /unknown tenant slot t9/],
];

for (const [name, change, message] of REFUSED) {
  test(`the guard refuses ${name}`, () => {
    const program = copy();
    const principals = structuredClone(STAGE2_PRINCIPALS);
    change(program, principals);
    assert.throws(() => validateStage2(program, { principals, closure }), message);
  });
}
