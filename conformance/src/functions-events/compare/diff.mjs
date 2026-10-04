// Pure comparison of flattened observations (see normalize.mjs). Reasons name paths, types,
// format features and short digests only, so a comparison file never carries a raw id, time,
// resource name or payload value (the corpus keeps those private).
import { createHash } from "node:crypto";
import { formatOf } from "./normalize.mjs";

const byText = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

const sortedUnion = (a, b) => [...new Set([...a.keys(), ...b.keys()])].sort(byText);

const isPrimitive = (leaf) => leaf.type !== "object" && leaf.type !== "array";

const sameList = (a, b) => a.length === b.length && a.every((item, index) => item === b[index]);

const sameMembers = (a, b) => sameList([...a].sort(byText), [...b].sort(byText));

/** A short digest that lets a reviewer find the value in the private record without printing it. */
export function valueDigest(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex").slice(0, 12);
}

function blocker() {
  const blocked = [];
  return {
    covers: (path) =>
      blocked.some((root) => path.startsWith(`${root}.`) || path.startsWith(`${root}[`)),
    add: (path) => blocked.push(path),
  };
}

/**
 * Derive the volatile set from production pass 1 and pass 2 (E8). A path is volatile when its value
 * (or an object's member order) differs; a format feature is volatile only when it differs as well.
 * A path present in one pass only, or with a different type, is a disagreement, never volatile.
 */
export function deriveVolatile(pass1, pass2, { orderIgnored = () => false } = {}) {
  const disagreements = [];
  const volatile = new Map();
  const skip = blocker();
  for (const path of sortedUnion(pass1, pass2)) {
    if (skip.covers(path)) continue;
    const a = pass1.get(path);
    const b = pass2.get(path);
    if (!a || !b) {
      disagreements.push(`production-presence ${path} (pass ${a ? 1 : 2} only)`);
      skip.add(path);
      continue;
    }
    if (a.type !== b.type) {
      disagreements.push(`production-type ${path} (${a.type}, ${b.type})`);
      skip.add(path);
      continue;
    }
    const features = new Set();
    if (a.type === "object") {
      if (!orderIgnored(path) && sameMembers(a.keys, b.keys) && !sameList(a.keys, b.keys))
        features.add("order");
    } else if (isPrimitive(a) && a.value !== b.value) {
      features.add("value");
      const fa = formatOf(a.value);
      const fb = formatOf(b.value);
      for (const key of new Set([...Object.keys(fa), ...Object.keys(fb)])) {
        if (fa[key] !== fb[key]) features.add(key);
      }
    }
    if (features.size > 0) volatile.set(path, new Set([...features].sort(byText)));
  }
  return { disagreements, volatile };
}

const shown = (feature) => (feature === undefined ? "none" : String(feature));

function formatReasons(label, path, reference, candidate, features) {
  const fr = formatOf(reference.value);
  const fc = formatOf(candidate.value);
  if (!features.has("kind") && fr.kind !== fc.kind) {
    return [`${label}: format ${path} kind (production ${fr.kind}, local ${fc.kind})`];
  }
  const reasons = [];
  for (const key of [...new Set([...Object.keys(fr), ...Object.keys(fc)])].sort(byText)) {
    if (features.has(key) || fr[key] === fc[key]) continue;
    reasons.push(
      `${label}: format ${path} ${key} (production ${shown(fr[key])}, local ${shown(fc[key])})`,
    );
  }
  return reasons;
}

/**
 * Compare a local observation with production pass 1 under the derived volatile set. Presence,
 * type, deterministic values, member order and the stable format features of volatile values
 * must all agree. Returns the reasons, empty when they agree. `orderIgnored(path)` names the objects whose member order is not
 * compared (the ruling that Gen2 Firestore document field maps are unordered); their values, presence and types still are.
 */
export function compareObservation(
  reference,
  volatile,
  candidate,
  label,
  { orderIgnored = () => false } = {},
) {
  const reasons = [];
  const skip = blocker();
  for (const path of sortedUnion(reference, candidate)) {
    if (skip.covers(path)) continue;
    const r = reference.get(path);
    const c = candidate.get(path);
    if (!c) {
      reasons.push(`${label}: missing-field ${path}`);
      skip.add(path);
      continue;
    }
    if (!r) {
      reasons.push(`${label}: extra-field ${path}`);
      skip.add(path);
      continue;
    }
    if (r.type !== c.type) {
      reasons.push(`${label}: type ${path} (production ${r.type}, local ${c.type})`);
      skip.add(path);
      continue;
    }
    const features = volatile.get(path) ?? new Set();
    if (r.type === "object") {
      if (
        !features.has("order") &&
        !orderIgnored(path) &&
        sameMembers(r.keys, c.keys) &&
        !sameList(r.keys, c.keys)
      ) {
        reasons.push(
          `${label}: order ${path} (production [${r.keys.join(",")}], local [${c.keys.join(",")}])`,
        );
      }
    } else if (isPrimitive(r)) {
      if (features.has("value")) {
        reasons.push(...formatReasons(label, path, r, c, features));
      } else if (r.value !== c.value) {
        reasons.push(
          `${label}: value ${path} (production ${r.type}#${valueDigest(r.value)}, local ${c.type}#${valueDigest(c.value)})`,
        );
      }
    }
  }
  return reasons;
}
