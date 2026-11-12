import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  FIRE_META,
  FIRE_NAME,
  LOAD_ONLY,
  OBJECTS,
  PROGRAMS,
  ROWS,
  SETTLE_MAX_POLLS,
  SETTLE_STREAK,
  expectedRequests,
  objectName,
  plannedNames,
  recordingPrefix,
  rowsOf,
  runRoot,
  staticBounds,
} from "./storage-rules-s9/plan.mjs";

const P = recordingPrefix("sr-0123abcd", 1);

describe("storage rules s9 plan", () => {
  it("has the rows the packet states, each on a known object or prefix", () => {
    assert.equal(ROWS.length, 32);
    assert.equal(new Set(ROWS.map((row) => row.id)).size, ROWS.length);
    assert.equal(LOAD_ONLY.length, 3);
    for (const row of ROWS) {
      assert.ok(
        PROGRAMS.some((p) => p.id === row.program),
        row.id,
      );
      if (row.op === "list") assert.equal(typeof row.prefix(P), "string", row.id);
      else assert.ok(OBJECTS[row.object], row.id);
    }
  });

  it("gives every object to exactly one program, and each program its marker", () => {
    const owner = new Map();
    for (const program of PROGRAMS) {
      assert.ok(program.objects.includes(program.marker), program.id);
      for (const id of program.objects) {
        assert.ok(OBJECTS[id], id);
        assert.equal(owner.has(id), false, `${id} belongs to two programs`);
        owner.set(id, program.id);
      }
    }
    assert.deepEqual([...owner.keys()].sort(), Object.keys(OBJECTS).sort());
    // A row reads an object of its own program, and no row reads a marker.
    const markers = new Set(PROGRAMS.map((p) => p.marker));
    for (const row of ROWS.filter((r) => r.op !== "list")) {
      assert.equal(owner.get(row.object), row.program, row.id);
      assert.equal(markers.has(row.object), false, row.id);
    }
    assert.equal(new Set(PROGRAMS.map((p) => p.marker)).size, PROGRAMS.length);
  });

  it("names the objects with the empty path segments of the audit (S9)", () => {
    assert.equal(objectName("pubPlain", P), `${P}/pub/x`);
    assert.equal(objectName("pubInterior", P), `${P}/pub//x`);
    assert.equal(objectName("pubLeading", P), `/${P}/pub/x`);
    assert.equal(objectName("pubTrailing", P), `${P}/pub/x/`);
    const source = PROGRAMS[0].source(P);
    assert.match(
      source,
      new RegExp(`match /${P.replaceAll("/", "\\/")}/pub/\\{f\\} \\{\\n      allow read: if true;`),
    );
    // The rule has no way to name an empty segment: one wildcard, one literal path.
    assert.equal(source.match(/match \//g).length, 3);
  });

  it("counts the supplementary character as two units and one point (S1-S4)", () => {
    assert.equal(FIRE_NAME.length, 4);
    assert.equal([...FIRE_NAME].length, 3);
    assert.equal(FIRE_META.length, 3);
    assert.equal([...FIRE_META].length, 2);
    const units = PROGRAMS[1].source(P);
    const full = objectName("s1r", P);
    assert.match(
      units,
      new RegExp(
        `${P}/s1r/\\{n\\} \\{\\n      allow read: if resource.name.size\\(\\) == ${full.length};`,
      ),
    );
    assert.match(
      units,
      new RegExp(
        `${P}/s1p/\\{n\\} \\{\\n      allow read: if resource.name.size\\(\\) == ${[...full].length};`,
      ),
    );
    assert.equal(full.length - [...full].length, 1);
    for (const needle of [
      "n.size() == 4;",
      "n.size() == 3;",
      "n[3] == 'x'",
      "n[2] == 'x'",
      `n[0:3] == 'é\u{1F525}'`,
      `n[0:2] == 'é\u{1F525}'`,
      "resource.metadata.k.size() == 3",
      "resource.metadata.k.size() == 2",
    ]) {
      assert.ok(units.includes(needle), needle);
    }
    assert.deepEqual(OBJECTS.s4a.metadata, { k: FIRE_META });
    assert.deepEqual(OBJECTS.s4c.metadata, { k: "ab" });
  });

  it("states the list rules of S10 and the load-only sources of S7 and S8", () => {
    const lists = PROGRAMS[2].source(P);
    assert.ok(lists.includes("allow list: if [file] != null;"));
    assert.ok(lists.includes(`allow list: if request.path == /b/$(bucket)/o/${P}/l3;`));
    assert.ok(
      lists.includes(`match /${P}/l4/{file} {\n      allow list: if true;`),
      "the single-segment form of the audit",
    );
    assert.ok(lists.includes(`match /${P}/l1/{file=**} {`), "the recursive form that lists match");
    assert.ok(lists.includes("allow list: if file == '';"));
    const byId = Object.fromEntries(LOAD_ONLY.map((item) => [item.id, item.source(P)]));
    assert.ok(byId["s7-lone-surrogate"].includes('"\\ud83d".size() == 1'));
    const before = byId["s8-function-before"];
    const after = byId["s8-function-after"];
    assert.ok(before.indexOf("function ok()") < before.indexOf("service firebase.storage"));
    assert.ok(after.indexOf("function ok()") > after.indexOf("service firebase.storage"));
    for (const source of [
      ...LOAD_ONLY.map((i) => i.source(P)),
      ...PROGRAMS.map((p) => p.source(P)),
    ]) {
      assert.ok(source.startsWith("rules_version = '2';\n"));
      assert.ok(source.length < 4096);
    }
  });

  it("keeps every name under the run root, with a fixed-length prefix", () => {
    const root = runRoot("sr-0123abcd");
    const names = plannedNames("sr-0123abcd");
    assert.equal(names.length, Object.keys(OBJECTS).length * 2);
    assert.equal(new Set(names).size, names.length);
    for (const name of names) assert.ok(name.replace(/^\//, "").startsWith(root), name);
    assert.equal(
      recordingPrefix("sr-0123abcd", 1).length,
      recordingPrefix("sr-ffffffff", 2).length,
    );
  });

  it("bounds the requests above the planned count, and both grow with the recordings", () => {
    for (const recordings of [1, 2, 3]) {
      const bounds = staticBounds(recordings);
      assert.ok(bounds.main >= expectedRequests(recordings), `${recordings}`);
      assert.ok(bounds.total > bounds.main);
    }
    assert.ok(staticBounds(2).main > staticBounds(1).main);
    assert.ok(expectedRequests(2) > expectedRequests(1));
    // A settle that takes the whole poll budget is inside the bound.
    assert.ok(SETTLE_MAX_POLLS > SETTLE_STREAK * 4);
    assert.equal(rowsOf("s9").length, 13);
    assert.equal(rowsOf("units").length, 13);
    assert.equal(rowsOf("lists").length, 6);
  });
});
