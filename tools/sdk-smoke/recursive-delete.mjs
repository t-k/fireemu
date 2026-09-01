import { initializeApp } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";

const app = initializeApp({ projectId: "demo-app" });
const db = getFirestore(app);
const results = [];
const check = (name, ok, extra) => results.push({ name, ok: !!ok, extra });

try {
  await db.recursiveDelete(db.doc("cleanup/empty"));
  check("empty root", true);

  await Promise.all([
    db.doc("cleanup/target").set({ keep: false }),
    db.doc("cleanup/target/children/a").set({ depth: 1 }),
    db.doc("cleanup/target/children/a/grandchildren/b").set({ depth: 2 }),
    db.doc("cleanup/sibling").set({ keep: true }),
  ]);
  await db.recursiveDelete(db.doc("cleanup/target"));
  const [target, child, grandchild, sibling] = await db.getAll(
    db.doc("cleanup/target"),
    db.doc("cleanup/target/children/a"),
    db.doc("cleanup/target/children/a/grandchildren/b"),
    db.doc("cleanup/sibling"),
  );
  check(
    "nested subtree",
    !target.exists && !child.exists && !grandchild.exists && sibling.exists,
    { target: target.exists, child: child.exists, grandchild: grandchild.exists, sibling: sibling.exists },
  );

  await db.doc("cleanup/missing/children/a").set({ depth: 1 });
  await db.recursiveDelete(db.doc("cleanup/missing"));
  const missingChild = await db.doc("cleanup/missing/children/a").get();
  check("missing root with descendants", !missingChild.exists, missingChild.exists);
} catch (error) {
  results.push({ name: "fatal", ok: false, extra: error.message });
}

console.log(JSON.stringify(results, null, 1));
process.exit(results.every((result) => result.ok) ? 0 : 1);
