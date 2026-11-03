"""The frame codec: `<decimal length>\\n<UTF-8 JSON object>`, the same bytes the Rust and Node sides speak."""

import io
import json
import random

import pytest

from fireemu_runner.framing import MAX_FRAME_BYTES, FrameWriter, ProtocolError, encode_frame, read_frame


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
    assert reason in str(error.value)


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
    with pytest.raises(ProtocolError, match="message fields"):
        read_frame(io.BytesIO(encode_frame(message)))


def test_an_invoke_without_an_entry_point_is_valid():
    message = invoke()
    assert "entryPoint" not in message
    assert read_frame(io.BytesIO(encode_frame(message))) == message


def test_the_largest_frame_is_accepted_and_one_more_byte_is_not():
    padding = "x" * (MAX_FRAME_BYTES - len(b'{"type":"shutdown","p":""}'))
    payload = ('{"type":"shutdown","p":"%s"}' % padding).encode()
    assert len(payload) == MAX_FRAME_BYTES
    assert read_frame(io.BytesIO(frame(payload)))["type"] == "shutdown"
    with pytest.raises(ProtocolError, match="frame too large"):
        read_frame(io.BytesIO(frame(payload + b" ")))


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
