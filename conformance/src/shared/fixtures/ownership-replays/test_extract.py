"""Tests of the decisions in extract.py, on small synthetic captures (no private run record needed).

Run by ownership.replay.test.mjs: python3 -m unittest test_extract
"""
import base64, json, unittest

import extract


def request(n, op, transport, name, response, at="2026-10-04T21:00:00.000Z"):
    if transport == "rest":
        req = {"method": "GET", "path": f"/v1/projects/p/{name}"}
    else:
        req = {"rpc": "Publisher/GetTopic", "body": {"topic": f"projects/p/{name}"}}
    return {"n": n, "at": at, "transport": transport, "op": op, "request": req, "response": response}


def complete(rows):
    count = len([r for r in rows if "n" in r])
    return rows + [{"at": "2026-10-04T22:00:00.000Z", "note": "run-end", "requests": count}]


class GrpcTable(unittest.TestCase):
    def test_is_the_canonical_google_rpc_mapping(self):
        self.assertEqual(extract.GRPC, {
            "OK": 200, "CANCELLED": 499, "UNKNOWN": 500, "INVALID_ARGUMENT": 400,
            "DEADLINE_EXCEEDED": 504, "NOT_FOUND": 404, "ALREADY_EXISTS": 409,
            "PERMISSION_DENIED": 403, "RESOURCE_EXHAUSTED": 429, "FAILED_PRECONDITION": 400,
            "ABORTED": 409, "OUT_OF_RANGE": 400, "UNIMPLEMENTED": 501, "INTERNAL": 500,
            "UNAVAILABLE": 503, "DATA_LOSS": 500, "UNAUTHENTICATED": 401})

    def test_maps_a_known_code_and_refuses_an_unknown_one(self):
        self.assertEqual(extract.grpc_status("PERMISSION_DENIED"), 403)
        with self.assertRaises(SystemExit) as raised:
            extract.grpc_status("BOGUS")
        self.assertIn("'BOGUS' is not in the table", str(raised.exception))


class Completeness(unittest.TestCase):
    ROW = request(1, "getTopic", "rest", "topics/a", {"status": 404})

    def refused(self, rows):
        with self.assertRaises(SystemExit) as raised:
            extract.pubsub_ops(rows, "cap.jsonl")
        self.assertIn("cap.jsonl is not a complete capture", str(raised.exception))

    def test_refuses_a_capture_without_the_run_end_note(self):
        self.refused([self.ROW])
        self.refused([])
        self.refused([self.ROW, {"note": "something-else", "requests": 1}])

    def test_refuses_a_run_end_with_a_short_or_long_count(self):
        self.refused([self.ROW, {"note": "run-end", "requests": 0}])
        self.refused([self.ROW, {"note": "run-end", "requests": 2}])

    def test_takes_a_complete_capture(self):
        ops, skipped = extract.pubsub_ops(complete([self.ROW]))
        self.assertEqual(len(ops), 1)
        self.assertEqual(skipped, 0)


class PubsubOps(unittest.TestCase):
    def ops(self, *rows):
        return extract.pubsub_ops(complete(list(rows)))

    def test_a_present_get_carries_the_name_its_body_shows(self):
        body = {"name": "projects/fireemu-oracle-idp/topics/a"}
        (op,), _ = self.ops(request(1, "getTopic", "rest", "topics/a", {"status": 200, "body": body}))
        self.assertEqual((op["action"], op["status"], op["bodyName"], op["name"]), ("get", 200, "topics/a", "topics/a"))
        self.assertEqual(op["at"], "2026-10-04T21:00:00.000Z")
        self.assertNotIn("transportError", op)

    def test_only_a_2xx_get_with_a_named_body_has_a_body_name(self):
        named = {"name": "projects/p/topics/a"}
        for status in (199, 300, 301, 404, 409, 500):
            (op,), _ = self.ops(request(1, "getTopic", "rest", "topics/a", {"status": status, "body": named}))
            self.assertNotIn("bodyName", op, status)
        for status in (200, 204, 299):
            (op,), _ = self.ops(request(1, "getTopic", "rest", "topics/a", {"status": status, "body": named}))
            self.assertIn("bodyName", op, status)
        (op,), _ = self.ops(request(1, "getTopic", "rest", "topics/a", {"status": 200, "body": {"x": 1}}))
        self.assertNotIn("bodyName", op)
        (op,), _ = self.ops(request(1, "getTopic", "rest", "topics/a", {"status": 200, "body": "text"}))
        self.assertNotIn("bodyName", op)
        (op,), _ = self.ops(request(1, "getTopic", "rest", "topics/a", {"unknown": True, "error": "timeout"}))
        self.assertEqual((op["status"], op["bodyReadable"], op["transportError"]), (None, False, "timeout"))
        self.assertNotIn("bodyName", op)

    def test_a_create_or_delete_never_has_a_body_name(self):
        named = {"name": "projects/p/topics/a"}
        ops, _ = self.ops(
            request(1, "createTopic", "rest", "topics/a", {"status": 200, "body": named}),
            request(2, "deleteTopic", "rest", "topics/a", {"status": 200, "body": named}))
        self.assertEqual([(o["action"], "bodyName" in o) for o in ops], [("create", False), ("delete", False)])

    def test_grpc_codes_become_http_statuses_and_the_name_comes_from_the_request(self):
        rows = [request(1, "getTopic", "grpc", "topics/a", {"code": "OK", "body": {"name": "projects/p/topics/a"}}),
                request(2, "createTopic", "grpc", "topics/b", {"code": "PERMISSION_DENIED"}),
                request(3, "deleteTopic", "grpc", "topics/c", {"code": "CANCELLED"})]
        ops, _ = self.ops(*rows)
        self.assertEqual([(o["name"], o["status"]) for o in ops], [("topics/a", 200), ("topics/b", 403), ("topics/c", 499)])
        self.assertEqual(ops[0]["bodyName"], "topics/a")

    def test_an_unmapped_grpc_code_stops_the_extraction(self):
        with self.assertRaises(SystemExit):
            self.ops(request(1, "getTopic", "grpc", "topics/a", {"code": "BOGUS"}))

    def test_a_list_request_is_skipped_and_counted_and_other_operations_are_ignored(self):
        ops, skipped = self.ops(
            request(1, "getTopic", "rest", "topics", {"status": 200, "body": {"topics": []}}),
            request(2, "getSubscription", "rest", "subscriptions", {"status": 200, "body": {}}),
            request(3, "getTopic", "grpc", "snapshots", {"code": "OK"}),
            request(4, "publish", "rest", "topics/a:publish", {"status": 200}),
            request(5, "getTopic", "rest", "topics/a", {"status": 404}))
        self.assertEqual(skipped, 3)
        self.assertEqual([o["name"] for o in ops], ["topics/a"])

    def test_scrubs_project_ids_and_numbers_from_names(self):
        (op,), _ = self.ops(request(1, "getTopic", "rest", "topics/fireemu-oracle-idp-123456789012", {"status": 404}))
        self.assertEqual(op["name"], "topics/demo-project-000000000000")


def entry(rid, status, url, body=None):
    before = {"id": rid, "url": url}
    response = {"id": rid, "status": status}
    if body is not None:
        response["bodyBase64"] = base64.b64encode(json.dumps(body).encode()).decode()
    return (rid, before, response)


class ShowsName(unittest.TestCase):
    URL = "https://pubsub.googleapis.com/v1/projects/p/topics/t1"

    def shows(self, body, url=URL, raw=None):
        e = entry("x", 200, url, body)
        if raw is not None:
            e[2]["bodyBase64"] = raw
        return extract.shows_name(e[1], e[2])

    def test_true_only_when_the_body_names_what_the_url_asks_for(self):
        self.assertTrue(self.shows({"name": "projects/p/topics/t1"}))
        self.assertFalse(self.shows({"name": "projects/p/topics/other"}))
        self.assertFalse(self.shows({"name": "projects/p/topics/t1"}, url="https://x/v1/projects/p/topics/t1/extra"))
        self.assertFalse(self.shows({"name": 5}))
        self.assertFalse(self.shows({"other": "projects/p/topics/t1"}))
        self.assertFalse(self.shows(["projects/p/topics/t1"]))
        self.assertFalse(extract.shows_name({"url": self.URL}, {}), "a response with no body")
        self.assertFalse(self.shows(None, raw="!!not base64 json!!"))

    def test_compares_only_the_last_path_segment(self):
        self.assertTrue(self.shows({"name": "t1"}))
        self.assertTrue(self.shows({"name": "a/b/c/t1"}, url="https://x/y/z/t1"))
        self.assertFalse(self.shows({"name": "projects/t1/topics/t2"}))


class SchedulerOps(unittest.TestCase):
    URL = "https://cloudscheduler.googleapis.com/v1/projects/p/locations/l/jobs/shape"
    OWN = {"name": "projects/p/locations/l/jobs/shape"}

    def gets(self, status, body):
        return extract.scheduler_ops([entry("before-job", status, self.URL, body)], [])

    def test_a_get_shows_its_name_only_for_a_2xx_whose_body_names_the_resource(self):
        (op,) = self.gets(200, self.OWN)
        self.assertEqual((op["action"], op["name"], op["status"], op["bodyName"]), ("get", "jobs/shape", 200, "jobs/shape"))
        self.assertIn("bodyName", self.gets(299, self.OWN)[0])
        for status in (199, 300, 404, 409):
            self.assertNotIn("bodyName", self.gets(status, self.OWN)[0], status)
        self.assertNotIn("bodyName", self.gets(200, {"name": "projects/p/locations/l/jobs/other"})[0])
        self.assertNotIn("bodyName", self.gets(200, None)[0])

    def test_maps_creates_deletes_and_calendar_entries(self):
        shape = [entry("create-topic", 200, "u"), entry("delete-job", 409, "u"), entry("read-deleted-subscription", 404, "u"),
                 entry("noise", 200, "u")]
        cal = [entry("c07-create", 400, "u"), entry("create-topic", 200, "u"), entry("c08-delete", 200, "u"), entry("other", 200, "u")]
        ops = extract.scheduler_ops(shape, cal)
        self.assertEqual([(o["action"], o["name"], o["status"]) for o in ops], [
            ("create", "topics/shape", 200), ("delete", "jobs/shape", 409), ("get", "subscriptions/shape", 404),
            ("create", "jobs/c07", 400), ("create", "topics/calendar", 200), ("delete", "jobs/c08", 200)])
        self.assertTrue(all(o["transport"] == "rest" and o["bodyReadable"] is True for o in ops))


if __name__ == "__main__":
    unittest.main()
