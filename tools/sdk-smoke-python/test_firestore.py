"""google-cloud-firestore (through firebase_admin.firestore) against fireemu over gRPC."""

import threading

import pytest
from firebase_admin import firestore
from google.cloud.firestore_v1 import ArrayUnion, Increment
from google.cloud.firestore_v1.base_query import FieldFilter


@pytest.fixture
def db(app):
    return firestore.client(app)


@pytest.fixture
def collection(db, unique):
    return db.collection(f"py-{unique}")


def test_set_get_update_delete(collection):
    ref = collection.document("a")
    ref.set({"name": "ada", "n": 1})
    snapshot = ref.get()
    assert snapshot.exists
    assert snapshot.to_dict() == {"name": "ada", "n": 1}
    ref.update({"n": 2, "extra": True})
    assert ref.get().to_dict() == {"name": "ada", "n": 2, "extra": True}
    ref.delete()
    assert not ref.get().exists


def test_where_order_by_limit(collection):
    for n in range(5):
        collection.document(f"d{n}").set({"n": n})
    query = (
        collection.where(filter=FieldFilter("n", ">=", 1))
        .order_by("n", direction=firestore.Query.DESCENDING)
        .limit(2)
    )
    assert [snapshot.get("n") for snapshot in query.stream()] == [4, 3]


def test_batch(db, collection):
    batch = db.batch()
    batch.set(collection.document("x"), {"v": 1})
    batch.set(collection.document("y"), {"v": 2})
    batch.commit()
    assert sorted(s.get("v") for s in collection.stream()) == [1, 2]
    batch = db.batch()
    batch.update(collection.document("x"), {"v": 10})
    batch.delete(collection.document("y"))
    batch.commit()
    assert [(s.id, s.get("v")) for s in collection.stream()] == [("x", 10)]


def test_transactional(db, collection):
    ref = collection.document("counter")
    ref.set({"count": 1})

    @firestore.transactional
    def bump(transaction):
        current = ref.get(transaction=transaction).get("count")
        transaction.update(ref, {"count": current + 1})
        return current + 1

    assert bump(db.transaction()) == 2
    assert ref.get().get("count") == 2


def test_on_snapshot_receives_an_update_and_unsubscribes(collection):
    ref = collection.document("watched")
    ref.set({"v": 0})
    seen = []
    initial = threading.Event()
    updated = threading.Event()

    def on_snapshot(snapshots, _changes, _read_time):
        for snapshot in snapshots:
            seen.append(snapshot.get("v"))
            (initial if snapshot.get("v") == 0 else updated).set()

    watch = ref.on_snapshot(on_snapshot)
    try:
        assert initial.wait(timeout=20), f"no initial snapshot, saw {seen}"
        ref.set({"v": 1})
        assert updated.wait(timeout=20), f"no update delivered, saw {seen}"
    finally:
        watch.unsubscribe()
    assert seen == [0, 1], seen
    ref.set({"v": 2})
    ref.get()
    assert seen == [0, 1], f"a snapshot arrived after unsubscribe: {seen}"


def test_array_union_increment_and_server_timestamp(collection):
    ref = collection.document("transforms")
    ref.set({"tags": ["a"], "count": 1})
    ref.update(
        {
            "tags": ArrayUnion(["a", "b"]),
            "count": Increment(2),
            "at": firestore.SERVER_TIMESTAMP,
        }
    )
    data = ref.get().to_dict()
    assert data["tags"] == ["a", "b"]
    assert data["count"] == 3
    assert data["at"] is not None and data["at"].year >= 2020
