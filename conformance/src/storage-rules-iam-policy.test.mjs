import assert from "node:assert/strict";
import test from "node:test";
import { GRANT_ROLE, assess, bindingsDigest, canonicalBindings, parsePolicy, sameBindings, setBody, storageAgentMember, withGrant, withoutGrant } from "./storage-rules-iam/policy.mjs";
import { createIamTargets } from "./storage-rules-iam/targets.mjs";
import { IDS, ALL_IDS, PREFLIGHT_IDS, iamCorpus } from "./storage-rules-iam/plan.mjs";
import { createIamHttpsTransport } from "./storage-rules-iam/transport.mjs";
import { MEMBER, NUMBERS, OTHER_BINDINGS, ownerDigest } from "./storage-rules-iam-support.mjs";

const policy = (bindings = OTHER_BINDINGS, extra = {}) => parsePolicy({ etag: "E1", version: 3, bindings, ...extra });

test("the member of the Cloud Storage for Firebase service agent is built from the project number only", () => {
  assert.equal(storageAgentMember("111111111111"), "serviceAccount:service-111111111111@gcp-sa-firebasestorage.iam.gserviceaccount.com");
  for (const bad of ["0", "012", "a", "", 5, null, "1/2", "1".repeat(21), "1 2"]) assert.throws(() => storageAgentMember(bad), /invalid project number/, String(bad));
  assert.equal(GRANT_ROLE, "roles/firebaserules.firestoreServiceAgent");
});

test("a policy is an etag, a version and bindings with members and an optional condition, read strictly", () => {
  const parsed = policy();
  assert.equal(parsed.etag, "E1");
  assert.equal(parsed.version, 3);
  assert.equal(parsed.bindings.length, OTHER_BINDINGS.length);
  assert.deepEqual(parsed.bindings[2].condition, OTHER_BINDINGS[2].condition);
  assert.notEqual(parsed.bindings[0].members, OTHER_BINDINGS[0].members);
  assert.equal(Object.isFrozen(parsed) && Object.isFrozen(parsed.bindings), true);
  assert.equal(parsePolicy({ etag: "e" }).bindings.length, 0);
  assert.equal(parsePolicy({ etag: "e" }).version, 0);
  for (const bad of [null, [], "x", {}, { etag: "" }, { etag: 5 }, { etag: "e".repeat(1025) }, { etag: "e", version: 4 }, { etag: "e", version: -1 }, { etag: "e", version: 1.5 }, { etag: "e", bindings: "x" },
    { etag: "e", bindings: [null] }, { etag: "e", bindings: [{ role: "", members: [] }] }, { etag: "e", bindings: [{ role: "r", members: "x" }] }, { etag: "e", bindings: [{ role: "r", members: [""] }] }, { etag: "e", bindings: [{ role: "r", members: [5] }] },
    { etag: "e", bindings: [{ role: "r", members: [], condition: "x" }] }, { etag: "e", bindings: Array.from({ length: 1501 }, () => ({ role: "r", members: [] })) }, { etag: "e", bindings: [{ role: "r".repeat(257), members: [] }] }, { etag: "e", bindings: [{ role: "r", members: ["m".repeat(513)] }] }, Object.create({ etag: "e" })]) {
    assert.throws(() => parsePolicy(bad), /invalid policy/, JSON.stringify(bad)?.slice(0, 80));
  }
});

test("the grant is absent, present once, or ambiguous (conditional, or more than once)", () => {
  assert.deepEqual(assess(policy(), MEMBER), { state: "absent" });
  assert.deepEqual(assess(policy([...OTHER_BINDINGS, { role: GRANT_ROLE, members: ["serviceAccount:other@example.test"] }]), MEMBER), { state: "absent" });
  assert.deepEqual(assess(policy([...OTHER_BINDINGS, { role: "roles/other", members: [MEMBER] }]), MEMBER), { state: "absent" });
  assert.deepEqual(assess(policy([...OTHER_BINDINGS, { role: GRANT_ROLE, members: [MEMBER] }]), MEMBER), { state: "present" });
  assert.equal(assess(policy([{ role: GRANT_ROLE, members: ["x", MEMBER, "y"] }]), MEMBER).state, "present");
  assert.match(assess(policy([{ role: GRANT_ROLE, members: [MEMBER], condition: { title: "t", expression: "true" } }]), MEMBER).reason, /conditional/);
  assert.match(assess(policy([{ role: GRANT_ROLE, members: [MEMBER, MEMBER] }]), MEMBER).reason, /more than once/);
  assert.match(assess(policy([{ role: GRANT_ROLE, members: [MEMBER] }, { role: GRANT_ROLE, members: [MEMBER] }]), MEMBER).reason, /more than once/);
  assert.equal(assess(policy([{ role: GRANT_ROLE, members: [MEMBER] }, { role: GRANT_ROLE, members: [MEMBER], condition: { title: "t", expression: "true" } }]), MEMBER).state, "ambiguous");
  assert.equal(assess(policy([{ role: GRANT_ROLE, members: [MEMBER.toUpperCase()] }]), MEMBER).state, "absent");
});

test("adding the grant keeps every binding and appends the member to the unconditional binding of the role, or adds one", () => {
  const before = policy();
  const added = withGrant(before, MEMBER);
  assert.equal(added.version, 3);
  assert.equal(added.etag, "E1");
  assert.deepEqual(added.bindings.slice(0, OTHER_BINDINGS.length), OTHER_BINDINGS);
  assert.deepEqual(added.bindings.at(-1), { role: GRANT_ROLE, members: [MEMBER] });
  assert.equal(assess(added, MEMBER).state, "present");
  assert.equal(Object.isFrozen(added) && Object.isFrozen(added.bindings), true);
  // The input is untouched.
  assert.equal(before.bindings.length, OTHER_BINDINGS.length);
  const appended = withGrant(policy([...OTHER_BINDINGS, { role: GRANT_ROLE, members: ["serviceAccount:other@example.test"] }, { role: GRANT_ROLE, members: ["user:c@example.test"], condition: { title: "c", expression: "true" } }]), MEMBER);
  assert.deepEqual(appended.bindings.filter((b) => b.role === GRANT_ROLE).map((b) => b.members), [["serviceAccount:other@example.test", MEMBER], ["user:c@example.test"]]);
  assert.deepEqual(appended.bindings.filter((b) => b.role === GRANT_ROLE)[1].condition, { title: "c", expression: "true" });
  // A conditional binding of the role does not receive the member: a new unconditional binding is added instead.
  const onlyConditional = withGrant(policy([{ role: GRANT_ROLE, members: ["user:c@example.test"], condition: { title: "c", expression: "true" } }]), MEMBER);
  assert.deepEqual(onlyConditional.bindings.map((b) => [b.members, b.condition ?? null]), [[["user:c@example.test"], { title: "c", expression: "true" }], [[MEMBER], null]]);
  for (const state of [policy([{ role: GRANT_ROLE, members: [MEMBER] }]), policy([{ role: GRANT_ROLE, members: [MEMBER], condition: { title: "t", expression: "true" } }])]) assert.throws(() => withGrant(state, MEMBER), /grant is not absent/);
});

test("removing the grant takes out exactly the member and drops the binding only when that emptied it", () => {
  const before = policy();
  const granted = withGrant(before, MEMBER);
  assert.equal(sameBindings(withoutGrant(policy(granted.bindings, { etag: "E2" }), MEMBER), before), true);
  const shared = policy([...OTHER_BINDINGS, { role: GRANT_ROLE, members: ["serviceAccount:other@example.test", MEMBER] }]);
  const removed = withoutGrant(shared, MEMBER);
  assert.deepEqual(removed.bindings.filter((b) => b.role === GRANT_ROLE).map((b) => b.members), [["serviceAccount:other@example.test"]]);
  assert.equal(removed.etag, "E1");
  assert.equal(removed.version, 3);
  for (const state of [before, policy([{ role: GRANT_ROLE, members: [MEMBER], condition: { title: "t", expression: "true" } }])]) assert.throws(() => withoutGrant(state, MEMBER), /grant is not present/);
  // A binding of another role that names the member is not touched.
  const other = policy([{ role: "roles/other", members: [MEMBER] }, { role: GRANT_ROLE, members: [MEMBER] }]);
  assert.deepEqual(withoutGrant(other, MEMBER).bindings, [{ role: "roles/other", members: [MEMBER] }]);
});

test("policies are compared without the order of bindings and members, with conditions in the comparison, and the digest never holds a member", () => {
  const a = policy([{ role: "b", members: ["y", "x"] }, { role: "a", members: ["m"], condition: { expression: "e", title: "t" } }]);
  const b = policy([{ role: "a", members: ["m"], condition: { title: "t", expression: "e" } }, { role: "b", members: ["x", "y", "x"] }]);
  assert.equal(sameBindings(a, b), true);
  assert.equal(bindingsDigest(a), bindingsDigest(b));
  for (const other of [[{ role: "b", members: ["y", "x"] }, { role: "a", members: ["m"], condition: { expression: "e2", title: "t" } }], [{ role: "b", members: ["y", "x"] }, { role: "a", members: ["m"] }], [{ role: "b", members: ["y"] }, { role: "a", members: ["m"], condition: { expression: "e", title: "t" } }], [{ role: "b", members: ["y", "x", "z"] }, { role: "a", members: ["m"], condition: { expression: "e", title: "t" } }]]) {
    assert.equal(sameBindings(a, policy(other)), false);
    assert.notEqual(bindingsDigest(a), bindingsDigest(policy(other)));
  }
  assert.match(bindingsDigest(a), /^[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(canonicalBindings(a)).includes("condition"), true);
});

test("the request body writes only the bindings and the etag, at policy version 3", () => {
  const body = setBody(withGrant(policy(), MEMBER));
  assert.deepEqual(Object.keys(body), ["policy", "updateMask"]);
  assert.equal(body.updateMask, "bindings,etag");
  assert.deepEqual(Object.keys(body.policy), ["version", "etag", "bindings"]);
  assert.equal(body.policy.version, 3);
  assert.equal(body.policy.etag, "E1");
  assert.deepEqual(body.policy.bindings[2].condition, OTHER_BINDINGS[2].condition);
  assert.equal(Object.hasOwn(body.policy.bindings[0], "condition"), false);
});

test("the ID lists: five on the normal path, three of them the preflight, three for the recovery, eight in all, each once", () => {
  assert.deepEqual([...PREFLIGHT_IDS], [IDS.token, IDS.identity, IDS.before]);
  assert.equal(ALL_IDS.length, 8);
  assert.equal(new Set(ALL_IDS).size, 8);
  assert.deepEqual(ALL_IDS.filter((id) => id.startsWith("recovery/")), [IDS.current, IDS.revoke, IDS.absent]);
  assert.deepEqual(ALL_IDS.filter((id) => id.startsWith("preflight/")), [...PREFLIGHT_IDS]);
  assert.deepEqual(ALL_IDS.filter((id) => !id.startsWith("recovery/") && !id.startsWith("preflight/")), [IDS.grant, IDS.after]);
});

test("the corpus digest follows the project, the role, the member and the owner digest, and it is stable", () => {
  const base = iamCorpus({ projectNumber: NUMBERS.query, ownerEmailSha256: ownerDigest });
  assert.equal(base.member, MEMBER);
  assert.equal(base.list.length, 8);
  assert.equal(iamCorpus({ projectNumber: NUMBERS.query, ownerEmailSha256: ownerDigest }).sha256, base.sha256);
  assert.notEqual(iamCorpus({ projectNumber: "333333333333", ownerEmailSha256: ownerDigest }).sha256, base.sha256);
  assert.notEqual(iamCorpus({ projectNumber: NUMBERS.query, ownerEmailSha256: "0".repeat(64) }).sha256, base.sha256);
  for (const bad of ["x", "0".repeat(63), "A".repeat(64), 5, undefined]) assert.throws(() => iamCorpus({ projectNumber: NUMBERS.query, ownerEmailSha256: bad }), /invalid owner digest/);
  const byId = Object.fromEntries(base.list.map((row) => [row.id, `${row.method} ${row.url}`]));
  assert.equal(byId[IDS.grant], `POST https://cloudresourcemanager.googleapis.com/v3/projects/${NUMBERS.query}:setIamPolicy`);
  assert.equal(byId[IDS.revoke], byId[IDS.grant]);
  assert.equal(byId[IDS.before], `POST https://cloudresourcemanager.googleapis.com/v3/projects/${NUMBERS.query}:getIamPolicy`);
  assert.equal(Object.isFrozen(base), true);
});

test("the targets build the read and the identity request from fixed sources and the set bodies from the policy that was read, and verify only what they issued", () => {
  const targets = createIamTargets({ projectNumber: NUMBERS.query, digestSalt: "7".repeat(64) });
  const read = targets.prepareRead(IDS.before);
  assert.equal(read.spec.url, `https://cloudresourcemanager.googleapis.com/v3/projects/${NUMBERS.query}:getIamPolicy`);
  assert.deepEqual(JSON.parse(read.spec.body.toString()), { options: { requestedPolicyVersion: 3 } });
  assert.deepEqual([read.credential, read.project, read.spec.method], ["admin", "fireemu-oracle-query", "POST"]);
  assert.equal(targets.verify(read), true);
  const identity = targets.prepareIdentity(IDS.identity);
  assert.deepEqual([identity.spec.url, identity.spec.method, identity.spec.body], ["https://www.googleapis.com/oauth2/v2/userinfo", "GET", null]);
  assert.equal(targets.verify(identity), true);
  const grant = targets.prepareGrant(IDS.grant, policy());
  assert.equal(grant.spec.url, `https://cloudresourcemanager.googleapis.com/v3/projects/${NUMBERS.query}:setIamPolicy`);
  assert.deepEqual(JSON.parse(grant.spec.body.toString()), setBody(withGrant(policy(), MEMBER)));
  assert.equal(grant.spec.headers["content-type"], "application/json; charset=utf-8");
  assert.equal(targets.verify(grant), true);
  const revoke = targets.prepareRevoke(IDS.revoke, parsePolicy({ etag: "E9", version: 3, bindings: withGrant(policy(), MEMBER).bindings }));
  assert.equal(JSON.parse(revoke.spec.body.toString()).policy.etag, "E9");
  assert.equal(JSON.parse(revoke.spec.body.toString()).policy.bindings.some((b) => b.members.includes(MEMBER)), false);
  // A grant is refused unless the grant is absent, a removal unless it is present.
  assert.throws(() => targets.prepareGrant(IDS.grant, policy([{ role: GRANT_ROLE, members: [MEMBER] }])), /not absent/);
  assert.throws(() => targets.prepareRevoke(IDS.revoke, policy()), /not present/);
  assert.equal(targets.member, MEMBER);
  // Copies, foreign objects and objects of another builder are not verified.
  for (const foreign of [{ ...read }, { ...grant }, null, {}, "x"]) assert.equal(targets.verify(foreign), false);
  assert.equal(createIamTargets({ projectNumber: NUMBERS.query, digestSalt: "8".repeat(64) }).verify(read), false);
});

test("the IAM transport allows the policy write for a plain POST to one project only, and every stage 3 route as before", () => {
  const transport = createIamHttpsTransport({ requestImpl() { throw new Error("must not send"); } });
  const set = (over = {}) => ({ url: `https://cloudresourcemanager.googleapis.com/v3/projects/${NUMBERS.query}:setIamPolicy`, method: "POST", headers: { "content-type": "application/json" }, body: Buffer.from("{}"), ...over });
  assert.doesNotThrow(() => transport.validate(set()));
  for (const bad of [set({ method: "GET", body: null }), set({ url: `${set().url}?x=1` }), set({ url: "https://cloudresourcemanager.googleapis.com/v3/projects/abc:setIamPolicy" }), set({ url: "https://cloudresourcemanager.googleapis.com/v3/projects/0:setIamPolicy" }), set({ url: "https://cloudresourcemanager.googleapis.com/v1/projects/1:setIamPolicy" }), set({ url: "https://cloudresourcemanager.googleapis.com/v3/projects/1:setIamPolicy/x" }), set({ url: "https://example.com/v3/projects/1:setIamPolicy" }), set({ url: "http://cloudresourcemanager.googleapis.com/v3/projects/1:setIamPolicy" }), set({ url: "https://cloudresourcemanager.googleapis.com/v3/projects/1:setOrgPolicy" })]) {
    assert.throws(() => transport.validate(bad), (error) => error.notSent === true, bad.url);
  }
  assert.doesNotThrow(() => transport.validate({ url: `https://cloudresourcemanager.googleapis.com/v3/projects/${NUMBERS.query}:getIamPolicy`, method: "POST", headers: {}, body: Buffer.from("{}") }));
  assert.doesNotThrow(() => transport.validate({ url: "https://www.googleapis.com/oauth2/v2/userinfo", method: "GET", headers: {}, body: null }));
  // The API key list route of stage 2a is not here.
  assert.throws(() => transport.validate({ url: `https://apikeys.googleapis.com/v2/projects/${NUMBERS.query}/locations/global/keys`, method: "GET", headers: {}, body: null }), (error) => error.notSent === true);
});
