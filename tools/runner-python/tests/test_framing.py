"""The frame codec: `<decimal length>\\n<UTF-8 JSON object>`, the same bytes the Rust and Node sides speak."""

import io
import json
import random

import pytest

from fireemu_runner.framing import MAX_FRAME_BYTES, FrameWriter, ProtocolError, encode_frame, raw_event_data, read_frame


def frame(payload: bytes) -> bytes:
    return str(len(payload)).encode() + b"\n" + payload


def invoke(**overrides):
    message = {"type": "invoke", "invocationId": "i-1", "function": "f", "trigger": "firestore", "event": {}}
    message.update(overrides)
    return message


def test_encode_is_decimal_length_newline_compact_utf8_json():
    assert encode_frame({"type": "hello", "x": "é"}) == frame('{"type":"hello","x":"é"}'.encode("utf-8"))


def test_a_frame_round_trips_through_the_reader():
    message = invoke(event={"a": [1, 2, {"b": None}], "s": "日本語"})
    assert read_frame(io.BytesIO(encode_frame(message))) == message


def test_frames_follow_each_other_and_a_clean_end_is_none():
    stream = io.BytesIO(encode_frame({"type": "shutdown"}) + encode_frame(invoke()))
    assert read_frame(stream) == {"type": "shutdown"}
    assert read_frame(stream)["type"] == "invoke"
    assert read_frame(stream) is None


@pytest.mark.parametrize(
    "raw, reason",
    [
        (b"\n{}", "empty length"),
        (b"0\n", "decimal length"),
        (b":\n{}", "decimal length"),
        (b"/\n{}", "decimal length"),
        (b"01\n{}", "decimal length"),
        (b"-1\n", "decimal length"),
        (b"1x\n", "decimal length"),
        (b"123456789\n", "frame too large"),
        (str(MAX_FRAME_BYTES + 1).encode() + b"\n", "frame too large"),
        (b"5\n{\"a\"", "truncated"),
        (b"12", "truncated"),
        (frame(b"\xff\xfe"), "UTF-8 or JSON"),
        (frame(b"not json"), "UTF-8 or JSON"),
        (frame(b"[1]"), "message object"),
        (frame(b'"s"'), "message object"),
    ],
)
def test_malformed_frames_are_refused_with_a_fixed_reason(raw, reason):
    with pytest.raises(ProtocolError) as error:
        read_frame(io.BytesIO(raw))
    assert str(error.value) == f"invalid runner frame ({reason})"


@pytest.mark.parametrize(
    "message",
    [
        {"type": "invoke", "function": "f", "trigger": "t", "event": {}},
        invoke(invocationId=""),
        invoke(invocationId=3),
        invoke(function=""),
        invoke(trigger=None),
        invoke(event=[]),
        invoke(event="x"),
        invoke(entryPoint=""),
        invoke(entryPoint=1),
        {"type": "unknown"},
        {"type": "clock:set", "invocationId": "c"},
        {},
    ],
)
def test_messages_that_are_not_shutdown_or_a_complete_invoke_are_refused(message):
    with pytest.raises(ProtocolError) as error:
        read_frame(io.BytesIO(encode_frame(message)))
    assert str(error.value) == "invalid runner frame (message fields)"


def test_an_invoke_without_an_entry_point_is_valid():
    message = invoke()
    assert "entryPoint" not in message
    assert read_frame(io.BytesIO(encode_frame(message))) == message


def test_the_largest_frame_is_accepted_and_one_more_byte_is_not():
    padding = "x" * (MAX_FRAME_BYTES - len(b'{"type":"shutdown","p":""}'))
    payload = ('{"type":"shutdown","p":"%s"}' % padding).encode()
    assert len(payload) == MAX_FRAME_BYTES
    assert read_frame(io.BytesIO(frame(payload)))["type"] == "shutdown"
    with pytest.raises(ProtocolError) as error:
        read_frame(io.BytesIO(frame(payload + b" ")))
    assert str(error.value) == "invalid runner frame (frame too large)"


def test_random_messages_round_trip():
    generator = random.Random(20261103)
    for _ in range(200):
        event = {f"k{index}": generator.choice([None, True, 1, 1.5, "s" * generator.randrange(40), "日本"]) for index in range(generator.randrange(8))}
        message = invoke(event=event, invocationId=f"i-{generator.randrange(10**6)}")
        assert read_frame(io.BytesIO(encode_frame(message))) == message


def test_the_writer_serialises_concurrent_frames():
    import threading

    class Recording(io.BytesIO):
        def write(self, data):
            # Tear a frame in two writes so an unlocked writer would interleave them.
            half = len(data) // 2
            super().write(data[:half])
            super().write(data[half:])
            return len(data)

    out = Recording()
    writer = FrameWriter(out)
    threads = [threading.Thread(target=lambda n=n: [writer.write(invoke(invocationId=f"{n}-{k}")) for k in range(50)]) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    out.seek(0)
    count = 0
    while (message := read_frame(out)) is not None:
        assert message["type"] == "invoke"
        count += 1
    assert count == 400


def test_a_frame_the_writer_cannot_fit_is_refused_and_the_largest_fits():
    from fireemu_runner.framing import MAX_FRAME_BYTES as cap

    base = len(encode_frame({"p": ""}).split(b"\n", 1)[1])
    fits = encode_frame({"p": "x" * (cap - base)})
    assert fits.split(b"\n", 1)[0] == str(cap).encode()
    with pytest.raises(ProtocolError) as error:
        encode_frame({"p": "x" * (cap - base + 1)})
    assert str(error.value) == "invalid runner frame (frame too large)"


def test_non_ascii_text_is_written_as_utf8_not_escaped():
    frame_bytes = encode_frame({"type": "log", "message": "日本語"})
    assert "日本語".encode("utf-8") in frame_bytes
    assert b"\\u" not in frame_bytes
    header, body = frame_bytes.split(b"\n", 1)
    assert int(header) == len(body)


def test_the_entry_point_must_be_a_non_empty_string_when_present():
    for value in ("", None, 7, [], {}):
        with pytest.raises(ProtocolError):
            read_frame(io.BytesIO(encode_frame(invoke(entryPoint=value))))
    assert read_frame(io.BytesIO(encode_frame(invoke(entryPoint="ok"))))["entryPoint"] == "ok"


def test_a_reader_stops_at_the_end_of_one_frame_and_leaves_the_next_unread():
    stream = io.BytesIO(encode_frame({"type": "shutdown"}) + b"trailing")
    read_frame(stream)
    assert stream.read() == b"trailing"


def test_digits_are_counted_across_the_whole_header():
    # A 3-digit length must be read as 3 digits, not as 1: the body below is exactly 100 bytes.
    payload = ('{"type":"shutdown","pad":"%s"}' % ("x" * 72)).encode()
    assert len(payload) == 100
    assert read_frame(io.BytesIO(frame(payload)))["pad"] == "x" * 72


def test_the_writer_flushes_each_frame_and_copes_with_a_stream_that_cannot():
    class Counting(io.BytesIO):
        flushes = 0

        def flush(self):
            Counting.flushes += 1

    writer = FrameWriter(Counting())
    writer.write({"a": 1})
    writer.write({"a": 2})
    assert Counting.flushes == 2

    class NoFlush:
        def __init__(self):
            self.data = b""

        def write(self, data):
            self.data += data

    out = NoFlush()
    FrameWriter(out).write({"a": 1})
    assert out.data == encode_frame({"a": 1})


# ---- the text of event.data, as the daemon framed it ---------------------------------------------------------------------------
# A custom Eventarc event in the strict profile carries the publisher's JSON text in the frame (`runtime.rs`, `raw_data`); the
# decoder turns it into Python values and forgets the text. `raw_event_data` returns the text of `event.data` as it stands in the
# frame, so a request body can be the publisher's bytes.


@pytest.mark.parametrize(
    "data",
    [
        '{ "run" : "pcrun-1" ,"label":"fraction" }',
        '{"a":1e-7,"b":1e20,"c":"\\u00e9","d":-0.0,"e":[1E3,0.10,{"f":null}]}',
        '"a \\"quoted\\" \\\\ text"',
        "[1, 2 , 3]",
        "12.50",
        "true",
        "null",
        "{}",
    ],
)
def test_the_text_of_event_data_is_returned_as_framed(data):
    text = '{"attempt":1,"event":{"id":"e","data":' + data + ',"type":"t"},"function":"f","trigger":"eventarc"}'
    assert raw_event_data(text) == data


def test_event_data_is_found_after_members_that_hold_braces_quotes_and_the_word_data():
    text = (
        '{"deadline":"{\\"data\\":1}","event":{"attributes":{"data":2,"x":"}\\"{"},"source":"s","data" : {"k":"v"}},"z":1}'
    )
    assert raw_event_data(text) == '{"k":"v"}'


@pytest.mark.parametrize(
    "text",
    [
        '{"event":{"id":"e"}}',
        '{"event":[]}',
        '{"event":"x"}',
        '{"other":{"data":1}}',
        '{"event":{"data":',
        '{"event":{"data":}}',
        "not json",
        "",
        "[]",
        '{"event":{"data":1',
    ],
)
def test_no_text_is_returned_when_event_data_is_absent_or_the_frame_is_malformed(text):
    assert raw_event_data(text) is None


def test_a_json_family_invoke_frame_carries_the_text_of_its_data():
    payload = '{"event":{"data":{"b":1e-7,"a":1},"id":"e"},"function":"f","invocationId":"i-1","trigger":"eventarc","type":"invoke"}'
    message = read_frame(io.BytesIO(frame(payload.encode())))
    assert message["rawEventData"] == '{"b":1e-7,"a":1}'
    assert message["event"]["data"] == {"b": 1e-7, "a": 1}


@pytest.mark.parametrize("trigger", ["eventarc", "pubsub", "storage", "database"])
def test_every_json_family_frame_carries_the_text(trigger):
    payload = json.dumps({"type": "invoke", "invocationId": "i", "function": "f", "trigger": trigger, "event": {"data": {"n": 1.0}}})
    assert read_frame(io.BytesIO(frame(payload.encode())))["rawEventData"] == '{"n": 1.0}'


@pytest.mark.parametrize("trigger", ["firestore", "schedule", "http"])
def test_other_frames_carry_no_text(trigger):
    payload = json.dumps({"type": "invoke", "invocationId": "i", "function": "f", "trigger": trigger, "event": {"data": {"n": 1}}})
    assert "rawEventData" not in read_frame(io.BytesIO(frame(payload.encode())))


def test_a_frame_without_event_data_carries_no_text():
    assert "rawEventData" not in read_frame(io.BytesIO(frame(json.dumps(invoke(trigger="eventarc", event={"id": "e"})).encode())))
