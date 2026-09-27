// AUTH-FS-CROSS stage 2: the listener and SDK conditions as one declarative program per
// recording. A recording holds one listen window of about 65 minutes (OX-3): the long-lived
// listeners open first, the short conditions run next, the principals' Auth state changes after
// them, and the long-lived listeners are probed by commits right after the change, 65 s later,
// and around their token's expiry. A state change is always followed by a commit (C5); an
// `observe` step only records events that arrive, and a quiet one is never read as absence.
//
// The orchestrator (stage2-orchestrator.mjs) interprets the steps; placeholders `UID(name)` and
// `TENANT(slot)` are resolved by the session. Listener references are `grpc-<name>` for a native
// stream and `<client>/<listener>` for an SDK listener.

import { integer, string } from "../fs-rules/programs/common.mjs";

export const STAGE2_RULESET = "cross2";
/** How long an observation collects events after its commit (or after it starts). */
export const WINDOW_MS = 12_000;
/**
 * The requests one SDK client may make (its guard refuses the next). A held client lives for the
 * whole window and refreshes its token; a short condition's client lives a minute or two.
 */
export const HELD_WIRE_CAP = 200;
export const SHORT_WIRE_CAP = 100;
/** A pending write and a switch back get longer: the SDK's streams restart first. */
const SLOW_WINDOW_MS = 20_000;

/**
 * Every principal is an email/password account the administrator creates, so a Web SDK client
 * can sign in to it; the two tenant principals share one local id (the surviving tenant is the
 * control of the deleted one).
 */
export const STAGE2_PRINCIPALS = {
  steady: { provider: "admin-password" },
  rev: { provider: "admin-password" },
  dis: { provider: "admin-password" },
  del: { provider: "admin-password" },
  claim: { provider: "admin-password" },
  alice: { provider: "admin-password" },
  bob: { provider: "admin-password" },
  "ten-t1": { provider: "admin-password", sameUid: true, tenant: "t1" },
  "ten-t2": { provider: "admin-password", sameUid: true, tenant: "t2" },
};
export const STAGE2_TENANTS = ["t1", "t2"];

const CONDITION = {
  transaction: "AUTH-FS-CROSS/sdk-optimistic-transaction",
  switch: "AUTH-FS-CROSS/listen-sign-out-and-switch",
  refresh: "AUTH-FS-CROSS/listen-token-refresh",
  revocation: "AUTH-FS-CROSS/listen-revocation-disable-delete",
  tenant: "AUTH-FS-CROSS/listen-tenant-deletion",
  pending: "AUTH-FS-CROSS/pending-write-across-switch",
};
export const STAGE2_CONDITIONS = Object.values(CONDITION);

/**
 * The long-lived listeners: one native stream and one Node SDK client per principal, each with
 * a document and a query target on its own documents. `steady` never changes: it is the
 * same-age control (109C) and the stream held past its token's expiry without a refresh.
 */
export const HELD = [
  { principal: "steady", conditions: [CONDITION.revocation, CONDITION.refresh] },
  {
    principal: "rev",
    change: { do: "auth", action: "revoke", principal: "rev" },
    conditions: [CONDITION.revocation],
  },
  {
    principal: "dis",
    change: { do: "auth", action: "disable", principal: "dis" },
    conditions: [CONDITION.revocation],
  },
  {
    principal: "del",
    change: { do: "auth", action: "delete-account", principal: "del" },
    conditions: [CONDITION.revocation],
  },
  {
    principal: "ten-t1",
    tenant: "t1",
    change: { do: "auth", action: "delete-tenant", tenant: "t1" },
    conditions: [CONDITION.tenant],
  },
  { principal: "ten-t2", tenant: "t2", conditions: [CONDITION.tenant] },
];

const VIAS = ["grpc", "sdk"];
const streamName = (held) => `grpc-${held.principal}`;
const clientName = (held) => `sdk-${held.principal}`;

/** The document a held listener watches through one transport. */
export function heldDoc(held, via) {
  return held.tenant ? `afc2-tenant/${held.tenant}-${via}` : `afc2-owned/${held.principal}-${via}`;
}

function heldFields(held, via, n) {
  return {
    owner: string(`UID(${held.principal})`),
    via: string(via),
    n: integer(n),
    ...(held.tenant ? { tenant: string(`TENANT(${held.tenant})`) } : {}),
  };
}

/** The equality filters of a held listener's query: its owner, tenant and transport. */
function heldWhere(held, via) {
  return [
    ["owner", `UID(${held.principal})`],
    ...(held.tenant ? [["tenant", `TENANT(${held.tenant})`]] : []),
    ["via", via],
  ];
}

const collectionOf = (doc) => doc.split("/")[0];
const heldListeners = (held) => [
  streamName(held),
  `${clientName(held)}/doc`,
  `${clientName(held)}/query`,
];
const heldWrites = (n) => HELD.flatMap((h) => VIAS.map((via) => heldWrite(h, via, n)));
const heldWrite = (held, via, n) => ({ doc: heldDoc(held, via), fields: heldFields(held, via, n) });

// ---- the short conditions ------------------------------------------------------------------

/** A client's scenario document name: `tag` tells the Node client's from the browser's. */
const scenario = (tag, variant) => `${tag}-${variant}`;
const witness = (tag, variant) => `sdk-steady/w-${scenario(tag, variant)}`;
const ownDoc = (principal, tag, variant) => `afc2-owned/${principal}-${scenario(tag, variant)}`;
const openDoc = (tag, variant) => `afc2-open/${scenario(tag, variant)}`;
const ownFields = (principal, tag, variant, n) => ({
  owner: string(`UID(${principal})`),
  via: string(scenario(tag, variant)),
  n: integer(n),
});
const openFields = (n) => ({ n: integer(n) });

/** A client of the short conditions: `node` runs the Web SDK in Node, `browser` in Chromium. */
const TRANSPORTS = { n: "node-sdk", b: "browser" };

function listenOwn(client, name, principal, tag, variant) {
  return { do: "sdk", client, op: "listen", name, path: ownDoc(principal, tag, variant) };
}
function listenOwnQuery(client, name, principal, tag, variant) {
  return {
    do: "sdk",
    client,
    op: "listen",
    name,
    collection: "afc2-owned",
    where: [
      ["owner", "==", `UID(${principal})`],
      ["via", "==", scenario(tag, variant)],
    ],
  };
}

/**
 * listen-sign-out-and-switch, sign-out half (catalog case 106 and its negative 106N): alice's
 * document, query and a signed-in-only document; sign out; commit; listen while signed out;
 * sign in again and listen again. The steady client watches the open document as the witness.
 */
function signOutSteps(tag) {
  const client = `${tag}-out`;
  const id = (step) => `${scenario(tag, "out")}/${step}`;
  const writes = (n) => [
    { doc: ownDoc("alice", tag, "out"), fields: ownFields("alice", tag, "out", n) },
    { doc: openDoc(tag, "out"), fields: openFields(n) },
  ];
  const observed = [`${client}/own`, `${client}/query`, `${client}/open`, witness(tag, "out")];
  return [
    { do: "client", client, transport: TRANSPORTS[tag], wireCap: SHORT_WIRE_CAP },
    { do: "sdk", client, op: "signIn", as: "alice" },
    listenOwn(client, "own", "alice", tag, "out"),
    listenOwnQuery(client, "query", "alice", tag, "out"),
    { do: "sdk", client, op: "listen", name: "open", path: openDoc(tag, "out") },
    {
      do: "probe",
      id: id("signed-in"),
      condition: CONDITION.switch,
      writes: writes(1),
      observe: observed,
    },
    { do: "sdk", client, op: "signOut", mark: id("sign-out") },
    {
      do: "observe",
      id: id("after-sign-out"),
      condition: CONDITION.switch,
      observe: observed,
      clients: [client],
      since: id("sign-out"),
    },
    {
      do: "probe",
      id: id("signed-out"),
      condition: CONDITION.switch,
      writes: writes(2),
      observe: observed,
    },
    listenOwn(client, "own-signed-out", "alice", tag, "out"),
    {
      do: "observe",
      id: id("listen-signed-out"),
      condition: CONDITION.switch,
      observe: [`${client}/own-signed-out`],
    },
    { do: "sdk", client, op: "signIn", as: "alice" },
    listenOwn(client, "own-again", "alice", tag, "out"),
    {
      do: "probe",
      id: id("signed-in-again"),
      condition: CONDITION.switch,
      writes: writes(3),
      observe: [...observed, `${client}/own-again`],
    },
    { do: "close-client", client },
  ];
}

/**
 * listen-sign-out-and-switch, switch half: alice's listeners, then a sign-in as bob without a
 * sign-out; commits alice's document (bob may not read it), the signed-in-only document (he
 * may) and bob's own, then bob listens to his.
 */
function switchSteps(tag) {
  const client = `${tag}-ab`;
  const id = (step) => `${scenario(tag, "ab")}/${step}`;
  const alice = (n) => ({
    doc: ownDoc("alice", tag, "ab"),
    fields: ownFields("alice", tag, "ab", n),
  });
  const bob = (n) => ({ doc: ownDoc("bob", tag, "ab"), fields: ownFields("bob", tag, "ab", n) });
  const open = (n) => ({ doc: openDoc(tag, "ab"), fields: openFields(n) });
  const observed = [`${client}/own`, `${client}/query`, `${client}/open`, witness(tag, "ab")];
  return [
    { do: "client", client, transport: TRANSPORTS[tag], wireCap: SHORT_WIRE_CAP },
    { do: "sdk", client, op: "signIn", as: "alice" },
    listenOwn(client, "own", "alice", tag, "ab"),
    listenOwnQuery(client, "query", "alice", tag, "ab"),
    { do: "sdk", client, op: "listen", name: "open", path: openDoc(tag, "ab") },
    {
      do: "probe",
      id: id("as-alice"),
      condition: CONDITION.switch,
      writes: [alice(1), open(1)],
      observe: observed,
    },
    { do: "sdk", client, op: "signIn", as: "bob", mark: id("switch") },
    {
      do: "observe",
      id: id("after-switch"),
      condition: CONDITION.switch,
      observe: observed,
      clients: [client],
      since: id("switch"),
    },
    {
      do: "probe",
      id: id("switched"),
      condition: CONDITION.switch,
      writes: [alice(2), open(2), bob(1)],
      observe: observed,
    },
    listenOwn(client, "bob-own", "bob", tag, "ab"),
    {
      do: "probe",
      id: id("bob-listens"),
      condition: CONDITION.switch,
      writes: [alice(3), open(3), bob(2)],
      observe: [...observed, `${client}/bob-own`],
    },
    { do: "close-client", client },
  ];
}

/**
 * pending-write-across-switch: with the network off, alice writes a document only she may
 * create; switch to bob (`ab`) or sign out (`out`); network on; switch back to alice. What the
 * backend receives is read from the client's wire records (the bearer's principal), its
 * settle events and the document as the owner reads it at each step.
 */
function pendingSteps(tag, variant) {
  const client = `${tag}-pend-${variant}`;
  const id = (step) => `${scenario(tag, `pend-${variant}`)}/${step}`;
  const doc = `afc2-pending/${scenario(tag, variant)}`;
  return [
    { do: "client", client, transport: TRANSPORTS[tag], wireCap: SHORT_WIRE_CAP },
    { do: "sdk", client, op: "signIn", as: "alice" },
    { do: "sdk", client, op: "offline" },
    {
      do: "sdk",
      client,
      op: "writeLater",
      writeId: "w",
      path: doc,
      data: { owner: "UID(alice)", n: 1 },
    },
    variant === "ab"
      ? { do: "sdk", client, op: "signIn", as: "bob" }
      : { do: "sdk", client, op: "signOut" },
    { do: "server", id: id("offline"), condition: CONDITION.pending, docs: [doc] },
    { do: "sdk", client, op: "online", mark: id("online") },
    {
      do: "observe",
      id: id("online"),
      condition: CONDITION.pending,
      clients: [client],
      since: id("online"),
      windowMs: SLOW_WINDOW_MS,
    },
    { do: "server", id: id("after-online"), condition: CONDITION.pending, docs: [doc] },
    { do: "sdk", client, op: "signIn", as: "alice", mark: id("back") },
    {
      do: "observe",
      id: id("back"),
      condition: CONDITION.pending,
      clients: [client],
      since: id("back"),
      windowMs: SLOW_WINDOW_MS,
    },
    { do: "server", id: id("after-back"), condition: CONDITION.pending, docs: [doc] },
    { do: "close-client", client },
  ];
}

/**
 * sdk-optimistic-transaction: the SDK reads, the parent changes the Auth state, then the commit
 * goes. The document's Rules let only the uid named in `by` write it, so the outcome tells
 * whose token the commit carried; the wire records say it directly. `control` changes nothing.
 */
function transactionSteps() {
  const client = "n-tx";
  const one = (variant, change) => {
    const doc = `afc2-tx/${variant}`;
    const id = (step) => `tx-${variant}/${step}`;
    return [
      {
        do: "sdk",
        client,
        op: "transaction",
        await: false,
        mark: id("start"),
        commandId: `tx-${variant}`,
        name: variant,
        reads: [doc],
        write: { path: doc, data: { by: "UID(alice)", n: 1 } },
      },
      { do: "await", client, event: "transaction-read", name: variant },
      ...change,
      { do: "sdk", client, op: "continueTransaction", name: variant },
      {
        do: "await",
        id: id("result"),
        condition: CONDITION.transaction,
        client,
        event: "result",
        commandId: `tx-${variant}`,
        since: id("start"),
      },
      { do: "server", id: id("server"), condition: CONDITION.transaction, docs: [doc] },
    ];
  };
  return [
    { do: "client", client, transport: TRANSPORTS.n, wireCap: SHORT_WIRE_CAP },
    { do: "sdk", client, op: "signIn", as: "alice" },
    ...one("control", []),
    ...one("signout", [{ do: "sdk", client, op: "signOut" }]),
    { do: "sdk", client, op: "signIn", as: "alice" },
    ...one("switch", [{ do: "sdk", client, op: "signIn", as: "bob" }]),
    { do: "close-client", client },
  ];
}

/**
 * listen-token-refresh, SDK half: listeners on documents readable only with claim `c`. Without
 * the claim they fail; add it and refresh, commit, listen again; remove it and refresh, commit.
 */
function claimSteps() {
  const client = "n-claim";
  const doc = "afc2-claim/n";
  const write = (n) => [{ doc, fields: { via: string("n"), n: integer(n) } }];
  const listeners = (suffix) => [
    { do: "sdk", client, op: "listen", name: `doc${suffix}`, path: doc },
    {
      do: "sdk",
      client,
      op: "listen",
      name: `query${suffix}`,
      collection: "afc2-claim",
      where: [["via", "==", "n"]],
    },
  ];
  const first = [`${client}/doc1`, `${client}/query1`];
  const second = [`${client}/doc2`, `${client}/query2`];
  return [
    { do: "client", client, transport: TRANSPORTS.n, wireCap: SHORT_WIRE_CAP },
    { do: "sdk", client, op: "signIn", as: "claim" },
    ...listeners("1"),
    { do: "observe", id: "claim/without-c", condition: CONDITION.refresh, observe: first },
    { do: "auth", action: "claims", principal: "claim", claims: { c: true } },
    { do: "sdk", client, op: "refreshToken" },
    {
      do: "probe",
      id: "claim/added",
      condition: CONDITION.refresh,
      writes: write(1),
      observe: first,
    },
    ...listeners("2"),
    {
      do: "probe",
      id: "claim/with-c",
      condition: CONDITION.refresh,
      writes: write(2),
      observe: [...first, ...second],
    },
    { do: "auth", action: "claims", principal: "claim", claims: {} },
    { do: "sdk", client, op: "refreshToken", mark: "claim/remove" },
    {
      do: "observe",
      id: "claim/after-remove",
      condition: CONDITION.refresh,
      observe: second,
      clients: [client],
      since: "claim/remove",
    },
    {
      do: "probe",
      id: "claim/removed",
      condition: CONDITION.refresh,
      writes: write(3),
      observe: second,
    },
    { do: "close-client", client },
  ];
}

// ---- the program ---------------------------------------------------------------------------

/** Documents every recording starts with; pending documents start absent. */
function seedDocuments() {
  const docs = heldWrites(0);
  for (const tag of Object.keys(TRANSPORTS)) {
    for (const variant of ["out", "ab"]) {
      docs.push({
        doc: ownDoc("alice", tag, variant),
        fields: ownFields("alice", tag, variant, 0),
      });
      docs.push({ doc: openDoc(tag, variant), fields: openFields(0) });
    }
    docs.push({ doc: ownDoc("bob", tag, "ab"), fields: ownFields("bob", tag, "ab", 0) });
  }
  docs.push({ doc: "afc2-claim/n", fields: { via: string("n"), n: integer(0) } });
  for (const variant of ["control", "signout", "switch"])
    docs.push({ doc: `afc2-tx/${variant}`, fields: { by: string("seed"), n: integer(0) } });
  return docs;
}

function heldSteps() {
  const steps = [];
  for (const held of HELD) {
    steps.push({
      do: "stream",
      name: streamName(held),
      as: held.principal,
      targets: [
        { targetId: 1, document: heldDoc(held, "grpc") },
        {
          targetId: 2,
          collection: collectionOf(heldDoc(held, "grpc")),
          where: heldWhere(held, "grpc"),
        },
      ],
    });
  }
  for (const held of HELD) {
    const client = clientName(held);
    steps.push(
      { do: "client", client, transport: "node-sdk", wireCap: HELD_WIRE_CAP },
      { do: "sdk", client, op: "signIn", as: held.principal },
      { do: "sdk", client, op: "listen", name: "doc", path: heldDoc(held, "sdk") },
      {
        do: "sdk",
        client,
        op: "listen",
        name: "query",
        collection: collectionOf(heldDoc(held, "sdk")),
        where: heldWhere(held, "sdk").map(([field, value]) => [field, "==", value]),
      },
    );
  }
  // The witness of the switch and sign-out conditions: a principal that never changes.
  for (const tag of Object.keys(TRANSPORTS))
    for (const variant of ["out", "ab"])
      steps.push({
        do: "sdk",
        client: "sdk-steady",
        op: "listen",
        name: `w-${scenario(tag, variant)}`,
        path: openDoc(tag, variant),
      });
  return steps;
}

const everyHeld = HELD.flatMap(heldListeners);

/** The expiry probes of every held listener: its own documents, at its own token's time. */
function expiryProbe(id, plus) {
  return {
    do: "expiry-probes",
    id,
    plus,
    conditions: [CONDITION.revocation, CONDITION.tenant, CONDITION.refresh],
    probes: HELD.flatMap((held) => [
      {
        token: { principal: held.principal },
        write: heldWrite(held, "grpc", plus < 0 ? 4 : 5),
        observe: [streamName(held)],
      },
      {
        token: { client: clientName(held) },
        write: heldWrite(held, "sdk", plus < 0 ? 4 : 5),
        observe: [`${clientName(held)}/doc`, `${clientName(held)}/query`],
      },
    ]),
  };
}

export const STAGE2_PROGRAM = {
  id: "auth-fs-cross/stage2/window",
  ruleset: STAGE2_RULESET,
  tenants: STAGE2_TENANTS,
  principals: Object.keys(STAGE2_PRINCIPALS),
  seed: seedDocuments(),
  steps: [
    ...heldSteps(),
    {
      do: "probe",
      id: "held/opened",
      conditions: [CONDITION.revocation, CONDITION.tenant, CONDITION.refresh],
      writes: heldWrites(1),
      observe: [
        ...everyHeld,
        witness("n", "out"),
        witness("n", "ab"),
        witness("b", "out"),
        witness("b", "ab"),
      ],
    },
    ...claimSteps(),
    ...transactionSteps(),
    ...signOutSteps("n"),
    ...switchSteps("n"),
    ...pendingSteps("n", "ab"),
    ...pendingSteps("n", "out"),
    ...signOutSteps("b"),
    ...switchSteps("b"),
    ...pendingSteps("b", "ab"),
    ...pendingSteps("b", "out"),
    ...HELD.filter((held) => held.change).map((held) => held.change),
    {
      do: "probe",
      id: "held/after-change",
      conditions: [CONDITION.revocation, CONDITION.tenant],
      writes: heldWrites(2),
      observe: everyHeld,
    },
    { do: "sleep", ms: 60_000 },
    {
      do: "probe",
      id: "held/after-change-65s",
      conditions: [CONDITION.revocation, CONDITION.tenant],
      writes: heldWrites(3),
      observe: everyHeld,
    },
    expiryProbe("held/exp-minus-60", -60),
    expiryProbe("held/exp-plus-35", 35),
    { do: "close-all", id: "held/life", conditions: STAGE2_CONDITIONS },
  ],
};
