// The effects of the Node SDK recording: the catalog adapter's dependencies (createDeps, which
// binds the real SDK) with the two things the migrated cases need changed. The public collection
// is shared, so a case's `rank` values live in a band of their own (the run's), and its query is
// bounded to that band instead of ranging over the whole collection; and a write marked `__txn`
// is committed together with the others of its group in one `runTransaction`.

import { createDeps } from "../../../tools/compat-broad/fs-listen-resume/listen_sdk_adapter.mjs";
import { PUBLIC_COLLECTION } from "./sdk-cases.mjs";

/** Ranks of one run: 1000 + (the run's last six digits) * 100, so runs do not overlap. */
export function bandOf(run) {
  let hash = 0;
  for (const char of String(run)) hash = (hash * 31 + char.charCodeAt(0)) % 1_000_000;
  return 1000 + hash * 100;
}

/** The constraints of a catalog query listener, as data, inside the run's rank band. */
export function queryConstraints(spec, base) {
  const [field, op, bound] = spec.where;
  if (field !== "rank" || op !== "<") throw new Error(`unsupported listener filter ${spec.where}`);
  const [orderField, direction] = spec.orderBy ?? ["rank", "asc"];
  return [
    ["where", "rank", ">=", base],
    ["where", "rank", "<", base + bound],
    ["orderBy", orderField, direction],
    [spec.limitToLast ? "limitToLast" : "limit", spec.limit ?? 10],
  ];
}

/** A public document's fields with `rank` moved into the band; other documents are unchanged. */
export function inBand(docPath, fields, base) {
  if (!docPath.startsWith(`${PUBLIC_COLLECTION}/`) || typeof fields.rank !== "number")
    return fields;
  return { ...fields, rank: fields.rank + base };
}

/**
 * Dependencies over the real SDK (`sdk`, the firebase modules) and `clients`
 * ({ name: { db, auth, app, account } }). `runTransaction` groups: writes with the same
 * `__txn.id` are held until the group's `size` is reached, then committed together.
 */
export function makeDeps({ sdk, clients, base, revoke = null }) {
  const deps = createDeps(sdk, clients, { revoke });
  const groups = new Map();
  const apply = (constraint) => {
    const [kind, ...args] = constraint;
    return sdk[kind](...args);
  };
  deps.firestore.onQuerySnapshot = (client, spec, options, onNext, onError) => {
    const collection = sdk.collection(clients[client].db, PUBLIC_COLLECTION);
    const query = sdk.query(collection, ...queryConstraints(spec, base).map(apply));
    return sdk.onSnapshot(query, options, {
      next: (snapshot) =>
        onNext({
          docs: snapshot.docs.map((entry) => entry.ref.path),
          changes: snapshot.docChanges().map((change) => ({
            type: change.type,
            path: change.doc.ref.path,
            oldIndex: change.oldIndex,
            newIndex: change.newIndex,
          })),
          fromCache: snapshot.metadata.fromCache,
          hasPendingWrites: snapshot.metadata.hasPendingWrites,
        }),
      error: onError,
    });
  };
  const plainSetDoc = deps.firestore.setDoc;
  deps.firestore.setDoc = async (client, docPath, fields) => {
    const { __txn: group, ...rest } = fields;
    const shifted = inBand(docPath, rest, base);
    if (!group) return plainSetDoc(client, docPath, shifted);
    const held = groups.get(group.id) ?? [];
    held.push([docPath, shifted]);
    groups.set(group.id, held);
    if (held.length < group.size) return undefined;
    groups.delete(group.id);
    const { db } = clients[client];
    return sdk.runTransaction(db, async (transaction) => {
      for (const [path, data] of held) transaction.set(sdk.doc(db, path), data);
    });
  };
  return deps;
}
