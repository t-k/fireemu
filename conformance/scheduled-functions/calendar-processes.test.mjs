import assert from "node:assert/strict";
import { test } from "node:test";
import { ownedProcessTracker, parseProcessSnapshot } from "./calendar-processes.mjs";

const row = (pid, ppid, comm = "node", args = "node local-owned.mjs") => ({
  pid,
  ppid,
  comm,
  args,
  uid: 501,
  started: "Thu Oct 1 00:00:00 2026",
  pgid: 50,
});

test("calendar process snapshot parser retains exact start, UID and command identity", () => {
  const values = parseProcessSnapshot(
    "  200 100 200 501 Thu Oct  1 00:00:00 2026 /usr/bin/node /usr/bin/node child.mjs --calendar-child input.json\n",
  );
  assert.deepEqual(values, [
    {
      pid: 200,
      ppid: 100,
      pgid: 200,
      uid: 501,
      started: "Thu Oct 1 00:00:00 2026",
      comm: "/usr/bin/node",
      args: "/usr/bin/node child.mjs --calendar-child input.json",
    },
  ]);
  assert.throws(() => parseProcessSnapshot("unreadable snapshot"), /snapshot/);
});

test("calendar process snapshot excludes only the exact observation subprocess PID", () => {
  const text =
    "200 100 200 501 Thu Oct 1 00:00:00 2026 ps ps real-owned-server\n300 100 300 501 Thu Oct 1 00:00:00 2026 ps ps observation-command\n";
  assert.deepEqual(
    parseProcessSnapshot(text, 300).map((value) => value.pid),
    [200],
  );
  assert.throws(() => parseProcessSnapshot(text, 1), /observer/);
});

test("calendar process tracker discovers only its own descendants regardless of snapshot ordering", () => {
  const tracker = ownedProcessTracker(row(100, 50, "python3", "python3 portctl.py run"));
  tracker.observe([
    row(400, 300),
    row(700, 50),
    row(300, 200, "fireemu", "fireemu exec"),
    row(200, 100),
    row(100, 50, "python3", "python3 portctl.py run"),
  ]);
  assert.deepEqual(
    tracker
      .owned()
      .map((value) => value.pid)
      .toSorted((a, b) => a - b),
    [100, 200, 300, 400],
  );
  assert.ok(!tracker.live([row(700, 50)]).length);
});

test("calendar process tracker retains adopted descendants when launcher already exited", () => {
  const root = row(100, 50),
    tracker = ownedProcessTracker(root);
  tracker.observe([root, row(200, 100), row(300, 200)]);
  const snapshot = [row(200, 1), row(300, 200), row(700, 1)];
  assert.deepEqual(
    tracker
      .live(snapshot)
      .map((value) => value.pid)
      .toSorted((a, b) => a - b),
    [200, 300],
  );
  tracker.observe([...snapshot, row(400, 300)]);
  assert.deepEqual(
    tracker.live([row(400, 1)]).map((value) => value.pid),
    [400],
  );
});

test("calendar process tracker never adopts or signals a reused PID and its foreign descendants", () => {
  const root = row(100, 50),
    tracker = ownedProcessTracker(root);
  tracker.observe([root, row(200, 100)]);
  const reused = row(200, 100, "foreign", "foreign session"),
    snapshot = [root, reused, row(300, 200)];
  tracker.observe(snapshot);
  assert.deepEqual(
    tracker.live(snapshot).map((value) => value.pid),
    [100],
  );
  assert.deepEqual(
    tracker
      .owned()
      .map((value) => value.pid)
      .toSorted((a, b) => a - b),
    [100, 200],
  );
});

test("calendar process tracker distinguishes UID and start identity even when command matches", () => {
  for (const change of [{ uid: 502 }, { started: "Thu Oct 1 00:00:01 2026" }]) {
    const root = row(100, 50),
      tracker = ownedProcessTracker(root);
    tracker.observe([root, row(200, 100)]);
    const snapshot = [root, { ...row(200, 100), ...change }, row(300, 200)];
    tracker.observe(snapshot);
    assert.deepEqual(
      tracker.present(snapshot).map((value) => value.pid),
      [100],
    );
    assert.deepEqual(
      tracker.live(snapshot).map((value) => value.pid),
      [100],
    );
    assert.ok(!tracker.owned().some((value) => value.pid === 300));
  }
});

test("calendar process tracker requires valid noncritical root identity and a readable snapshot", () => {
  for (const value of [
    row(1, 0),
    { ...row(100, 50), comm: "" },
    { ...row(100, 50), started: "" },
    { ...row(100, 50), uid: -1 },
  ])
    assert.throws(() => ownedProcessTracker(value), /invalid.*identity/);
  const tracker = ownedProcessTracker(row(100, 50));
  assert.throws(() => tracker.observe(null), /snapshot/);
});

test("owned isolated group retains a previously unseen orphan helper after its leader exits", () => {
  const root = row(100, 50),
    leader = { ...row(200, 100), pgid: 200 },
    tracker = ownedProcessTracker(root, { branchPid: 200 });
  tracker.observe([root, leader]);
  const helper = { ...row(300, 1), pgid: 200 };
  tracker.observe([root, helper]);
  assert.deepEqual(
    tracker.live([root, helper]).map((r) => r.pid),
    [100, 300],
  );
});

test("an unknown foreign-UID member of a retained isolated group leaves explicit group debt", () => {
  const root = row(100, 50),
    leader = { ...row(200, 100), pgid: 200 },
    tracker = ownedProcessTracker(root, { branchPid: 200 });
  tracker.observe([root, leader]);
  const foreign = { ...row(300, 1), pgid: 200, uid: 999 };
  tracker.observe([root, foreign]);
  assert.equal(tracker.groupDebt(), true);
  assert.ok(!tracker.owned().some((r) => r.pid === 300));
});

test("known births remain present during terminal command text changes until actually absent", () => {
  const root = row(100, 50),
    leader = { ...row(200, 100), pgid: 200 },
    tracker = ownedProcessTracker(root, { branchPid: 200 });
  tracker.observe([root, leader]);
  const dying = { ...leader, comm: "(node)", args: "(node)" };
  tracker.observe([root, dying]);
  assert.equal(
    tracker.present([root, dying]).some((r) => r.pid === 200),
    true,
  );
  assert.equal(
    tracker.live([root, dying]).some((r) => r.pid === 200),
    false,
  );
  assert.equal(tracker.groupDebt(), true);
  tracker.observe([root]);
  assert.equal(tracker.groupDebt(), false);
});
test("a positively acquired utility with a different UID does not permanently taint its owned group", () => {
  const root = row(100, 50),
    leader = { ...row(200, 100), pgid: 200 },
    tracker = ownedProcessTracker(root, { branchPid: 200 }),
    utility = { ...row(300, 200, "ps", "/bin/ps -p 200"), pgid: 200, uid: 0 };
  tracker.observe([root, leader, utility]);
  assert.equal(tracker.groupDebt(), false);
  tracker.observe([root]);
  assert.equal(tracker.groupDebt(), false);
});

test("an acquired utility birth stays owned while its terminal command text changes", () => {
  const root = row(100, 50),
    leader = { ...row(200, 100), pgid: 200 },
    utility = { ...row(300, 200, "ps", "/bin/ps -p 200"), pgid: 200, uid: 0 },
    tracker = ownedProcessTracker(root, { branchPid: 200 });
  tracker.observe([root, leader, utility]);
  const dying = { ...utility, comm: "(ps)", args: "(ps)" };
  tracker.observe([root, leader, dying]);
  assert.equal(tracker.groupDebt(), false);
  assert.ok(tracker.present([root, leader, dying]).some((r) => r.pid === 300));
  assert.ok(!tracker.live([root, leader, dying]).some((r) => r.pid === 300));
});

test("a changed-birth group captain permanently disables orphan acquisition after departure", () => {
  const root = row(100, 50),
    leader = { ...row(200, 100), pgid: 200 },
    tracker = ownedProcessTracker(root, { branchPid: 200 });
  tracker.observe([root, leader]);
  const replacement = { ...leader, ppid: 1, started: "Thu Oct 1 00:00:01 2026" },
    orphan = { ...row(300, 1), pgid: 200, started: replacement.started };
  tracker.observe([root, replacement, orphan]);
  tracker.observe([root, orphan]);
  assert.equal(tracker.groupDebt(), true);
  assert.ok(!tracker.owned().some((value) => value.pid === orphan.pid));
  assert.ok(!tracker.live([root, orphan]).some((value) => value.pid === orphan.pid));
});

test("same-birth group metadata debt persists until a readable zero-members snapshot", () => {
  for (const captainReturns of [false, true]) {
    const root = row(100, 50),
      leader = { ...row(200, 100), pgid: 200 },
      peer = { ...row(300, 200), pgid: 200 },
      tracker = ownedProcessTracker(root, { branchPid: 200 });
    tracker.observe([root, leader, peer]);
    tracker.observe([root, { ...leader, comm: "(node)", args: "(node)" }, peer]);
    assert.equal(tracker.groupDebt(), true);
    tracker.observe([root, ...(captainReturns ? [leader] : []), { ...peer, ppid: 1 }]);
    assert.equal(tracker.groupDebt(), true);
    tracker.observe([root]);
    assert.equal(tracker.groupDebt(), false);
  }
});
