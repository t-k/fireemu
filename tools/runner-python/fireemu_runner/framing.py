"""The frame codec: `<decimal byte length>\\n<UTF-8 JSON object>`.

It matches `crates/fireemu-adapter-functions/src/protocol.rs` and `tools/runner-node/protocol.mjs`:
a canonical decimal length (no sign, no leading zero, at most 8 digits), a cap of 16 MiB, and only
the daemon messages this runner serves (`invoke` and `shutdown`). Diagnostics are fixed strings:
a JSON parser error can quote the payload.
"""

import json
import threading

MAX_FRAME_BYTES = 16 * 1024 * 1024
_MAX_HEADER_DIGITS = len(str(MAX_FRAME_BYTES))


class ProtocolError(Exception):
    """A frame the runner cannot accept; the reason is a fixed string."""

    def __init__(self, reason: str):
        super().__init__(f"invalid runner frame ({reason})")


def encode_frame(message: dict) -> bytes:
    payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > MAX_FRAME_BYTES:
        raise ProtocolError("frame too large")
    return str(len(payload)).encode("ascii") + b"\n" + payload


_DECODER = json.JSONDecoder()
_WHITESPACE = " \t\n\r"
# The trigger types whose request body is the event's JSON data as the daemon framed it.
_RAW_DATA_TRIGGERS = frozenset(("eventarc", "pubsub", "storage", "database"))


def _after_whitespace(text: str, index: int) -> int:
    while index < len(text) and text[index] in _WHITESPACE:
        index += 1
    return index


def raw_event_data(text: str) -> str | None:
    """The text of `event.data` exactly as it stands in a frame, or None when the frame has none or is malformed.

    The decoder turns the data into Python values and forgets its spelling (`1e-7`, `\\u00e9`, member order, white space).
    For a custom Eventarc event in the strict profile the daemon frames the publisher's own JSON text, and that text is the
    request body production delivered, so it is read here from the frame text, member by member, without parsing the data.
    """
    try:
        index = _after_whitespace(text, 0)
        for wanted in ("event", "data"):
            if text[index] != "{":
                return None
            index += 1
            while True:
                index = _after_whitespace(text, index)
                key, index = _DECODER.raw_decode(text, index)
                index = _after_whitespace(text, index)
                if text[index] != ":" or not isinstance(key, str):
                    return None
                index = _after_whitespace(text, index + 1)
                if key == wanted:
                    break
                index = _after_whitespace(text, _DECODER.raw_decode(text, index)[1])
                if text[index] == ",":
                    index += 1
        start = index
        end = _DECODER.raw_decode(text, start)[1]
        # A value must be followed by what ends it, or the frame is cut short.
        return text[start:end] if text[_after_whitespace(text, end)] in ",}" else None
    except (IndexError, ValueError):
        return None


def _text(value) -> bool:
    return isinstance(value, str) and len(value) > 0


def _decode_message(payload: bytes) -> dict:
    try:
        text = payload.decode("utf-8")
        message = json.loads(text)
    except (UnicodeDecodeError, ValueError):
        raise ProtocolError("UTF-8 or JSON") from None
    if not isinstance(message, dict):
        raise ProtocolError("message object")
    if message.get("type") == "shutdown":
        return message
    if (
        message.get("type") != "invoke"
        or not _text(message.get("invocationId"))
        or not _text(message.get("function"))
        or not _text(message.get("trigger"))
        or not isinstance(message.get("event"), dict)
        or ("entryPoint" in message and not _text(message["entryPoint"]))
    ):
        raise ProtocolError("message fields")
    if message["trigger"] in _RAW_DATA_TRIGGERS and "data" in message["event"]:
        raw = raw_event_data(text)
        if raw is not None:
            message["rawEventData"] = raw
    return message


def read_frame(stream) -> dict | None:
    """Reads one message from a binary stream; `None` at a clean end between frames."""
    length = 0
    digits = 0
    while True:
        byte = stream.read(1)
        if not byte:
            if digits == 0:
                return None
            raise ProtocolError("truncated")
        value = byte[0]
        if value == 10:
            if digits == 0:
                raise ProtocolError("empty length")
            break
        if value < 48 or value > 57 or (digits == 0 and value == 48):
            raise ProtocolError("decimal length")
        digits += 1
        length = length * 10 + value - 48
        if digits > _MAX_HEADER_DIGITS or length > MAX_FRAME_BYTES:
            raise ProtocolError("frame too large")
    payload = stream.read(length)
    if len(payload) != length:
        raise ProtocolError("truncated")
    return _decode_message(payload)


class FrameWriter:
    """Writes frames to the protocol channel, one whole frame at a time."""

    def __init__(self, stream):
        self._stream = stream
        self._lock = threading.Lock()

    def write(self, message: dict) -> None:
        data = encode_frame(message)
        with self._lock:
            self._stream.write(data)
            flush = getattr(self._stream, "flush", None)
            if flush is not None:
                flush()
