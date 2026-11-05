"""The JSON writer of the request bodies, pinned with literal texts (nothing here is computed by `json.dumps`)."""

from fireemu_runner import bodies
from fireemu_runner.events import eventarc_request


def parsed(text):
    return bodies.parse_keeping_numbers(text)


def test_compact_text_keeps_every_number_as_written_and_writes_characters_as_utf8():
    text = '{ "é" : [ ] , "b" : { } , "n" : -0 , "m" : [ 1E3 , { "z" : 0.10 } ] , "k" : 1e-7 , "s" : "é\\n" , "t" : true , "u" : null }'
    assert bodies.compact(parsed(text)) == '{"é":[],"b":{},"n":-0,"m":[1E3,{"z":0.10}],"k":1e-7,"s":"é\\n","t":true,"u":null}'


def test_a_member_name_is_written_as_utf8_in_every_layout():
    assert bodies.compact({"é": 1}) == '{"é":1}'
    assert bodies.write({"é": 1}, indent=2) == '{\n  "é": 1\n}'
    assert bodies.pubsub_layout({"é": 1}) == '{"é":1}\n'


def test_the_indented_layout_nests_objects_and_arrays_two_spaces_per_level():
    text = '{"a":[{"b":[1,{"c":null}]},[]],"é":{}}'
    assert bodies.write(parsed(text), indent=2) == (
        '{\n  "a": [\n    {\n      "b": [\n        1,\n        {\n          "c": null\n        }\n      ]\n    },\n    []\n  ],\n  "é": {}\n}'
    )


def test_a_compact_array_has_no_white_space_at_any_depth():
    assert bodies.compact(parsed('[1, [2, [3, {"a": [4]}]]]')) == '[1,[2,[3,{"a":[4]}]]]'


def test_sorting_reaches_the_objects_inside_arrays():
    assert bodies.write(parsed('[{"b":1,"a":[{"d":1,"c":2}]}]'), sort_keys=True) == '[{"a":[{"c":2,"d":1}],"b":1}]'
    assert bodies.pubsub_layout(parsed('{"z":[{"b":1,"a":2}],"a":1}')) == '{"a":1,"z":[{"a":2,"b":1}]}\n'


def test_without_sorting_the_given_member_order_is_kept_inside_arrays():
    assert bodies.compact(parsed('[{"b":1,"a":2}]')) == '[{"b":1,"a":2}]'


def test_a_storage_resource_has_its_known_members_first_and_sorts_the_rest_at_every_depth():
    text = '{"zz":[{"b":1,"a":2}],"name":"o","kind":"storage#object","metadata":{"y":1,"x":[{"q":1,"p":2}]}}'
    assert bodies.storage_layout(parsed(text)) == (
        '{\n  "kind": "storage#object",\n  "name": "o",\n'
        '  "metadata": {\n    "x": [\n      {\n        "p": 2,\n        "q": 1\n      }\n    ],\n    "y": 1\n  },\n'
        '  "zz": [\n    {\n      "a": 2,\n      "b": 1\n    }\n  ]\n}\n'
    )


def test_an_integer_keeps_its_sign_and_zeros_as_written():
    assert bodies.compact(parsed("[-0,0,10,-5]")) == "[-0,0,10,-5]"
    assert isinstance(parsed("[-0]")[0], bodies.Number)
    assert isinstance(parsed("[1.0]")[0], bodies.Number)


def test_a_delivery_of_an_event_without_data_has_no_bytes_in_either_body():
    delivery = eventarc_request({"specversion": "1.0", "id": "e", "source": "//s", "type": "t"})
    assert delivery.event_body == b"" and delivery.request_body == b""
