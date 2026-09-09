"""Descriptor extraction checks preserve nested schemas and streaming transports."""

from google.protobuf.descriptor_pb2 import FileDescriptorSet
from protobuf_inventory import surfaces


def test_nested_messages_oneofs_enum_values_and_stream_roles_are_retained():
    descriptor = FileDescriptorSet()
    file = descriptor.file.add(
        name="google/firestore/v1/example.proto", package="google.firestore.v1"
    )
    message = file.message_type.add(name="Request")
    message.field.add(name="value", number=1, type=9)
    message.oneof_decl.add(name="choice")
    message.nested_type.add(name="Nested").field.add(name="inner", number=1, type=9)
    message.enum_type.add(name="Mode").value.add(name="UNKNOWN", number=0)
    service = file.service.add(name="Firestore")
    service.method.add(
        name="Listen",
        input_type=".google.firestore.v1.Request",
        output_type=".google.firestore.v1.Response",
        server_streaming=True,
    )
    rows = surfaces(descriptor)
    pairs = {(row["locator"], row["kind"]) for row in rows}
    assert ("google.firestore.v1.Request.Nested.inner", "field") in pairs
    assert ("google.firestore.v1.Request.choice", "oneof") in pairs
    assert ("google.firestore.v1.Request.Mode.UNKNOWN", "enum-value") in pairs
    assert next(row for row in rows if row["kind"] == "response")["streaming"]
    assert all(row["classification"] == "unknown" for row in rows)
