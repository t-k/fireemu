// The signer role and binding (owner ledger 2216): the pure policy edits, the settlement rules and
// the steps against a fake IAM, including every failure path that must still remove the access.

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { GuardError } from "./storage-signed-put/guard.mjs";
import {
  IamStop,
  MIN_WINDOW_MINUTES,
  assertGrantShape,
  assertRemovalShape,
  conditionFor,
  holdsRole,
  normalizePolicy,
  ourBinding,
  roleBody,
  roleName,
  samePolicy,
  settleIam,
  signerRoles,
  storageVerdict,
  validateMember,
  validateWindow,
  withBinding,
  withoutBinding,
} from "./storage-signed-put/iam.mjs";
import { MAX_WINDOW_MINUTES, ROLE_ID, SIGNER_PERMISSION } from "./storage-signed-put/plan.mjs";

const PROJECT = "demo-project";
const MEMBER = "user:owner@example.com";
const ours = ourBinding({
  project: PROJECT,
  member: MEMBER,
  runId: "sp-0123abcd",
  endMs: Date.UTC(2026, 10, 3, 13, 0, 0, 999),
});

function prng(seed) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
  return {
    int: (n) => Math.floor(next() * n),
    pick: (l) => l[Math.floor(next() * l.length)],
    chance: (p) => next() < p,
  };
}

function randomPolicy(rnd) {
  const roles = [
    "roles/viewer",
    "roles/editor",
    "roles/iam.serviceAccountUser",
    `projects/${PROJECT}/roles/other`,
  ];
  const members = [
    "user:a@example.com",
    "user:b@example.com",
    "group:g@example.com",
    `serviceAccount:s@${PROJECT}.iam.gserviceaccount.com`,
    MEMBER,
  ];
  const bindings = [];
  for (let i = 0; i < rnd.int(5); i += 1) {
    const binding = {
      role: rnd.pick(roles),
      members: Array.from({ length: 1 + rnd.int(3) }, () => rnd.pick(members)).filter(
        (m, k, all) => all.indexOf(m) === k,
      ),
    };
    if (rnd.chance(0.3)) {
      binding.condition = {
        title: `t${rnd.int(3)}`,
        expression: `request.time < timestamp("2030-01-0${1 + rnd.int(8)}T00:00:00Z")`,
      };
    }
    bindings.push(binding);
  }
  const policy = { version: rnd.pick([1, 3]), etag: `etag-${rnd.int(1000)}` };
  if (bindings.length) policy.bindings = bindings;
  return policy;
}

describe("signer role inputs", () => {
  it("accepts only user:<email> as the member", () => {
    assert.equal(validateMember(MEMBER), MEMBER);
    for (const bad of [
      undefined,
      "",
      "owner@example.com",
      "group:g@example.com",
      "serviceAccount:s@x.iam.gserviceaccount.com",
      "user:",
      "user:a b@example.com",
      "user:a@example",
      "user:a@example.com\n",
      "allUsers",
      "allAuthenticatedUsers",
      "domain:example.com",
      "user:*@example.com",
    ]) {
      assert.throws(() => validateMember(bad), GuardError, String(bad));
    }
  });

  it("accepts a whole number of minutes between the minimum and the maximum", () => {
    for (const ok of [MIN_WINDOW_MINUTES, 60, MAX_WINDOW_MINUTES])
      assert.equal(validateWindow(ok), ok);
    for (const bad of [
      MIN_WINDOW_MINUTES - 1,
      MAX_WINDOW_MINUTES + 1,
      0,
      -5,
      60.5,
      Number.NaN,
      "60",
      undefined,
    ]) {
      assert.throws(() => validateWindow(bad), GuardError, String(bad));
    }
    assert.deepEqual([MIN_WINDOW_MINUTES, MAX_WINDOW_MINUTES], [10, 180]);
  });

  it("builds a time condition that ends at the given second, and the role body with signBlob only", () => {
    const condition = conditionFor("sp-0123abcd", Date.UTC(2026, 10, 3, 13, 0, 0, 999));
    assert.equal(condition.title, "storage-signed-put-sp-0123abcd");
    assert.equal(condition.expression, 'request.time < timestamp("2026-11-03T13:00:00Z")');
    assert.deepEqual(roleBody().role.includedPermissions, [SIGNER_PERMISSION]);
    assert.equal(roleBody().roleId, ROLE_ID);
    assert.equal(SIGNER_PERMISSION, "iam.serviceAccounts.signBlob");
    assert.equal(roleName(PROJECT), `projects/${PROJECT}/roles/fireemuAdminSdkSigner`);
    assert.deepEqual(ours.members, [MEMBER]);
    assert.equal(ours.role, roleName(PROJECT));
  });
});

describe("policy edits", () => {
  it("compares policies apart from the etag, the version and the order", () => {
    const a = {
      etag: "x",
      version: 1,
      bindings: [
        { role: "roles/a", members: ["user:1@e.co", "user:2@e.co"] },
        { role: "roles/b", members: ["user:3@e.co"] },
      ],
    };
    const b = {
      etag: "y",
      version: 3,
      bindings: [
        { role: "roles/b", members: ["user:3@e.co"] },
        { role: "roles/a", members: ["user:2@e.co", "user:1@e.co"] },
      ],
    };
    assert.equal(samePolicy(a, b), true);
    assert.equal(samePolicy(a, { ...b, bindings: [b.bindings[0]] }), false);
    assert.equal(samePolicy(a, { ...b, auditConfigs: [{ service: "allServices" }] }), false);
    assert.equal(samePolicy({ etag: "x" }, { etag: "y", bindings: [] }), true);
    const conditional = {
      role: "roles/a",
      members: ["user:1@e.co"],
      condition: { title: "t", expression: "e" },
    };
    assert.equal(
      samePolicy(
        { bindings: [conditional] },
        { bindings: [{ ...conditional, condition: { title: "t", expression: "other" } }] },
      ),
      false,
    );
    assert.equal(
      samePolicy(
        { bindings: [conditional] },
        { bindings: [{ role: "roles/a", members: ["user:1@e.co"] }] },
      ),
      false,
    );
    assert.deepEqual(normalizePolicy(undefined), { bindings: [], auditConfigs: [] });
  });

  it("adds exactly the run's binding at version 3, and refuses a policy that already holds the role", () => {
    const before = {
      version: 1,
      etag: "e1",
      bindings: [{ role: "roles/viewer", members: ["user:a@example.com"] }],
    };
    const after = withBinding(before, ours);
    assert.equal(after.version, 3);
    assert.equal(after.etag, "e1");
    assert.deepEqual(after.bindings, [...before.bindings, ours]);
    assert.deepEqual(before.bindings.length, 1, "the input is not changed");
    assert.equal(holdsRole(after, ours.role), true);
    assert.equal(holdsRole(before, ours.role), false);
    assert.throws(() => withBinding(after, ours), IamStop);
    assert.throws(
      () => withBinding({ bindings: [{ role: ours.role, members: ["user:x@example.com"] }] }, ours),
      IamStop,
    );
    assert.deepEqual(withBinding({ etag: "e" }, ours).bindings, [ours]);
  });

  it("removes only the run's binding: the same role for another member or condition stays", () => {
    const other = {
      role: ours.role,
      members: ["user:other@example.com"],
      condition: ours.condition,
    };
    const otherCondition = {
      role: ours.role,
      members: [MEMBER],
      condition: { ...ours.condition, title: "other" },
    };
    const shared = {
      role: ours.role,
      members: [MEMBER, "user:other@example.com"],
      condition: ours.condition,
    };
    const base = {
      etag: "e",
      bindings: [{ role: "roles/viewer", members: ["user:a@example.com"] }, other, otherCondition],
    };
    assert.deepEqual(
      withoutBinding({ ...base, bindings: [...base.bindings, ours] }, ours).bindings,
      base.bindings,
    );
    assert.deepEqual(withoutBinding({ ...base, bindings: [shared] }, ours).bindings, [
      { ...shared, members: ["user:other@example.com"] },
    ]);
    assert.deepEqual(withoutBinding(base, ours).bindings, base.bindings, "nothing to remove");
    assert.deepEqual(withoutBinding({ etag: "e" }, ours).bindings, []);
  });

  it("shape checks pass only for exactly the run's binding", () => {
    const before = {
      version: 1,
      etag: "e1",
      bindings: [{ role: "roles/viewer", members: ["user:a@example.com"] }],
    };
    const granted = { ...withBinding(before, ours), etag: "e1" };
    assert.doesNotThrow(() => assertGrantShape(before, granted, ours));
    const bad = [
      { ...granted, bindings: [...granted.bindings, { role: "roles/owner", members: [MEMBER] }] },
      { ...granted, bindings: [granted.bindings[1]] },
      {
        ...granted,
        bindings: [
          { ...granted.bindings[0], members: ["user:a@example.com", MEMBER] },
          granted.bindings[1],
        ],
      },
      { ...granted, etag: "e2" },
      { ...granted, bindings: [granted.bindings[0], { ...ours, members: ["allUsers"] }] },
      { ...granted, bindings: [granted.bindings[0], { ...ours, role: "roles/owner" }] },
      { ...granted, auditConfigs: [{ service: "allServices" }] },
    ];
    for (const policy of bad)
      assert.throws(() => assertGrantShape(before, policy, ours), GuardError);
    const removal = { ...before, etag: "e3" };
    assert.doesNotThrow(() => assertRemovalShape({ ...granted, etag: "e3" }, removal, ours));
    for (const policy of [
      { ...removal, bindings: [] },
      { ...removal, bindings: [...removal.bindings, ours] },
      { ...removal, bindings: [...removal.bindings, { role: "roles/owner", members: [MEMBER] }] },
      { ...removal, etag: "e4" },
    ]) {
      assert.throws(() => assertRemovalShape({ ...granted, etag: "e3" }, policy, ours), GuardError);
    }
  });

  it("property: granting then removing returns any policy that lacked the role, and grant changes nothing else", () => {
    const rnd = prng(0x1a31);
    let checked = 0;
    for (let i = 0; i < 300; i += 1) {
      const before = randomPolicy(rnd);
      if (holdsRole(before, ours.role)) continue;
      checked += 1;
      const granted = withBinding(before, ours);
      assert.deepEqual(granted.bindings.slice(0, -1), before.bindings ?? []);
      assert.deepEqual(granted.bindings.at(-1), ours);
      assert.doesNotThrow(() => assertGrantShape(before, { ...granted, etag: before.etag }, ours));
      const removed = withoutBinding(granted, ours);
      assert.equal(samePolicy(removed, before), true, JSON.stringify(before));
      assert.doesNotThrow(() =>
        assertRemovalShape({ ...granted, etag: "x" }, { ...removed, etag: "x" }, ours),
      );
      // any one-binding tamper of the written policy is refused
      const tampered = {
        ...granted,
        etag: before.etag,
        bindings: [
          ...granted.bindings,
          { role: rnd.pick(["roles/owner", "roles/editor"]), members: [MEMBER] },
        ],
      };
      assert.throws(() => assertGrantShape(before, tampered, ours), GuardError);
    }
    assert.ok(checked > 200);
  });

  it("property: removal on a policy changed by someone else keeps their changes", () => {
    const rnd = prng(0x77aa);
    for (let i = 0; i < 200; i += 1) {
      const original = randomPolicy(rnd);
      if (holdsRole(original, ours.role)) continue;
      const granted = withBinding(original, ours);
      const extra = { role: "roles/browser", members: ["user:late@example.com"] };
      const concurrent = { ...granted, bindings: [...granted.bindings, extra] };
      const removed = withoutBinding(concurrent, ours);
      assert.equal(
        samePolicy(removed, { ...original, bindings: [...(original.bindings ?? []), extra] }),
        true,
      );
    }
  });
});

describe("what the signer may already do", () => {
  const signer = `firebase-adminsdk-fbsvc@${PROJECT}.iam.gserviceaccount.com`;
  const member = `serviceAccount:${signer}`;

  it("lists the roles bound to the signer without a condition, from every policy read", () => {
    const project = {
      bindings: [
        { role: "roles/b", members: [member, "user:x@e.co"] },
        { role: "roles/a", members: [member] },
        { role: "roles/c", members: ["user:x@e.co"] },
        { role: "roles/d", members: [member], condition: { title: "t" } },
      ],
    };
    const bucket = {
      bindings: [
        { role: "roles/a", members: [member] },
        { role: "roles/storage.objectAdmin", members: [member] },
      ],
    };
    assert.deepEqual(signerRoles(signer, [project, bucket]), {
      roles: ["roles/a", "roles/b", "roles/storage.objectAdmin"],
      conditional: 1,
    });
    assert.deepEqual(signerRoles(signer, [{}, undefined]), { roles: [], conditional: 0 });
    assert.deepEqual(
      signerRoles(signer, [
        {
          bindings: [
            {
              role: "roles/a",
              members: [`serviceAccount:other@${PROJECT}.iam.gserviceaccount.com`],
            },
          ],
        },
      ]).roles,
      [],
    );
  });

  it("requires object create, get and delete together, across roles", () => {
    const defs = (...sets) => new Map(sets.map((s, i) => [`r${i}`, s]));
    assert.deepEqual(
      storageVerdict(
        defs(["storage.objects.create", "storage.objects.get", "storage.objects.delete"]),
      ),
      { ok: true, missing: [] },
    );
    assert.deepEqual(
      storageVerdict(
        defs(["storage.objects.create"], ["storage.objects.get", "storage.objects.delete", "x"]),
      ),
      { ok: true, missing: [] },
    );
    assert.deepEqual(storageVerdict(defs(["storage.objects.create", "storage.objects.get"])), {
      ok: false,
      missing: ["storage.objects.delete"],
    });
    assert.deepEqual(
      storageVerdict(defs(["storage.objects.list", "storage.buckets.get"])).missing,
      ["storage.objects.create", "storage.objects.get", "storage.objects.delete"],
    );
    assert.deepEqual(storageVerdict(new Map()), {
      ok: false,
      missing: ["storage.objects.create", "storage.objects.get", "storage.objects.delete"],
    });
  });
});

describe("settlement of the IAM changes", () => {
  const ev = (resource, event, extra = {}) => ({ resource, event, ...extra });
  const clean = [
    ev("role", "create", { status: 200 }),
    ev("binding", "grant", { status: 200 }),
    ev("binding", "read", { status: 200, present: true }),
    ev("binding", "read", { status: 200, present: true }),
    ev("binding", "remove", { status: 200 }),
    ev("binding", "final-read", { status: 200, equalsPreflight: true, present: false }),
    ev("role", "delete", { status: 200 }),
    ev("role", "final-read", { status: 200, deleted: true }),
  ];
  const reasons = (events) =>
    settleIam(events, { touched: true }).map((u) => `${u.name}: ${u.reason}`);

  it("settles nothing when nothing was touched, and a clean grant and removal", () => {
    assert.deepEqual(settleIam([], { touched: false }), []);
    assert.deepEqual(reasons(clean), []);
  });

  it("keeps an unknown grant open unless an own positive read shows the binding", () => {
    for (const status of [500, 503, 302, 100, Number.NaN]) {
      const unknown = [
        ev("role", "create", { status: 200 }),
        ev("binding", "grant", { status }),
        ev("binding", "final-read", { status: 200, equalsPreflight: true, present: false }),
        ev("role", "delete", { status: 200 }),
        ev("role", "final-read", { status: 200, deleted: true }),
      ];
      assert.deepEqual(
        reasons(unknown),
        ["signer binding: unknown grant, no positive read"],
        String(status),
      );
      const positive = [
        unknown[0],
        unknown[1],
        ev("binding", "read", { status: 200, present: true }),
        ev("binding", "remove", { status: 200 }),
        ...unknown.slice(2),
      ];
      assert.deepEqual(reasons(positive), [], String(status));
    }
  });

  it("keeps an unknown removal open for good, whatever is read afterwards", () => {
    for (const status of [500, 302, 99, Number.NaN]) {
      const events = clean.map((e) => (e.event === "remove" ? { ...e, status } : e));
      assert.deepEqual(reasons(events), ["signer binding: unknown removal"], String(status));
      assert.deepEqual(reasons([...events, ev("binding", "remove", { status: 200 })]), [
        "signer binding: unknown removal",
      ]);
    }
  });

  it("requires the final policy to equal the preflight one and the binding to be gone", () => {
    const swap = (patch) =>
      clean.map((e) =>
        e.event === "final-read" && e.resource === "binding" ? { ...e, ...patch } : e,
      );
    assert.deepEqual(reasons(swap({ equalsPreflight: false })), [
      "signer policy: does not equal the preflight policy apart from the etag",
    ]);
    assert.deepEqual(reasons(swap({ present: true })), [
      "signer policy: does not equal the preflight policy apart from the etag",
    ]);
    assert.deepEqual(
      reasons(clean.filter((e) => !(e.resource === "binding" && e.event === "final-read"))),
      ["signer binding: granted, not read back after removal"],
    );
  });

  it("settles a refused grant, and keeps a created role open until it is deleted and read back deleted", () => {
    assert.deepEqual(
      reasons([
        ev("role", "create", { status: 200 }),
        ev("binding", "grant", { status: 409 }),
        ev("binding", "final-read", { status: 200, equalsPreflight: true, present: false }),
        ev("role", "delete", { status: 200 }),
        ev("role", "final-read", { status: 200, deleted: true }),
      ]),
      [],
    );
    const noDelete = clean.filter((e) => !(e.resource === "role" && e.event !== "create"));
    assert.deepEqual(reasons(noDelete), ["signer role: created, not deleted"]);
    const notDeleted = clean.map((e) =>
      e.resource === "role" && e.event === "final-read" ? { ...e, deleted: false } : e,
    );
    assert.deepEqual(reasons(notDeleted), ["signer role: deleted, not read back as deleted"]);
    const unknownDelete = clean.map((e) =>
      e.resource === "role" && e.event === "delete" ? { ...e, status: 503 } : e,
    );
    assert.deepEqual(reasons(unknownDelete), ["signer role: unknown delete"]);
  });

  it("never settles an unknown role create by a 404", () => {
    for (const status of [500, 302, Number.NaN]) {
      assert.deepEqual(
        reasons([
          ev("role", "create", { status }),
          ev("role", "delete", { status: 404 }),
          ev("role", "final-read", { status: 404, deleted: false }),
        ]),
        ["signer role: unknown create, no positive read and delete"],
      );
      assert.deepEqual(reasons([ev("role", "create", { status })]), [
        "signer role: unknown create, no positive read and delete",
      ]);
      assert.deepEqual(
        reasons([
          ev("role", "create", { status }),
          ev("role", "delete", { status: 200 }),
          ev("role", "final-read", { status: 200, deleted: true }),
        ]),
        [],
      );
    }
    assert.deepEqual(
      reasons([ev("role", "create", { status: 409 })]),
      [],
      "a refused create made nothing",
    );
  });
});
