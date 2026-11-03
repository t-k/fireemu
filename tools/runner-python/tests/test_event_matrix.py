"""A pairwise matrix over the JSON event families: family, profile, content type, time form, variant.

The rows were generated with PICT from a model of those five factors (pairwise, with the seed rows below
forced in: every family with its defaults, the strict profile with a whole-second time, a Pub/Sub message with an
ordering key). Each row is run through the real runner. The oracle is independent of the adapters: a delivery
succeeds, except that the strict profile hands `storage_fn` and `eventarc_fn` a whole-second time as production's
event would carry it, which their `%f` parsing refuses.
"""

import pytest

from harness import Runner
from test_json_events import changed, custom, published, stored

ROWS = [
    ("pubsub", "emulator", "absent", "fraction", "base"),
    ("pubsub", "emulator", "json", "fraction", "rich"),
    ("storage", "emulator", "json", "fraction", "base"),
    ("storage", "strict", "absent", "whole_second", "base"),
    ("storage", "emulator", "absent", "whole_second", "base"),
    ("eventarc", "strict", "absent", "fraction", "base"),
    ("eventarc", "emulator", "json", "whole_second", "rich"),
    ("database", "emulator", "json", "fraction", "base"),
    ("database", "strict", "absent", "fraction", "rich"),
    ("database", "emulator", "json_charset", "whole_second", "rich"),
    ("eventarc", "strict", "json_charset", "fraction", "base"),
    ("pubsub", "strict", "json_charset", "whole_second", "rich"),
    ("storage", "emulator", "json_charset", "fraction", "rich"),
    ("storage", "strict", "json", "whole_second", "base"),
]

CONTENT_TYPES = {"absent": None, "json": "application/json", "json_charset": "application/json; charset=utf-8"}
TIMES = {"fraction": "2026-01-01T00:00:02.250Z", "whole_second": "2026-01-01T00:00:02Z"}


@pytest.fixture(scope="module")
def runners():
    started = {"emulator": Runner(), "strict": Runner(extra_env={"FIREEMU_HTTP_PROFILE": "strict"})}
    for process in started.values():
        process.hello()
    yield started
    for process in started.values():
        process.kill()


def build(family, time_form, variant):
    time = TIMES[time_form]
    rich = variant == "rich"
    if family == "pubsub":
        event = published("m-matrix", ordering_key="k" if rich else None, publish_time=time)
        event["time"] = time
        return "ps_orders", event
    if family == "storage":
        extra = {"metadata": {"a": "b"}, "timeDeleted": "2026-01-01T00:00:01.000Z"} if rich else {}
        return "st_finalized", stored("finalized", time=time, **extra)
    if family == "eventarc":
        extra = {"subject": "things/7", "colour": "red"} if rich else {}
        return "ea_plain", custom(time=time, **extra)
    event = changed("written", "messages/r1/m9", {"v": 1}, {"v": 2}, auth=None if rich else ("app_user", "u"), emulator_shape=False)
    event["time"] = time
    return "db_written", event


@pytest.mark.parametrize("family, profile, content_type, time_form, variant", ROWS)
def test_each_row_is_delivered_or_refused_as_the_oracle_says(runners, family, profile, content_type, time_form, variant):
    function, event = build(family, time_form, variant)
    if CONTENT_TYPES[content_type] is not None:
        event["datacontenttype"] = CONTENT_TYPES[content_type]
    expected = not (profile == "strict" and time_form == "whole_second" and family in ("storage", "eventarc"))
    process = runners[profile]
    trigger = {"pubsub": "pubsub", "storage": "storage", "eventarc": "eventarc", "database": "database"}[family]
    before = len([entry for entry in process.seen() if entry["function"] == function])
    result = process.invoke(f"matrix-{len(process.frames)}", function, trigger, event)
    assert result["ok"] is expected, result
    after = len([entry for entry in process.seen() if entry["function"] == function])
    assert after - before == (1 if expected else 0)
