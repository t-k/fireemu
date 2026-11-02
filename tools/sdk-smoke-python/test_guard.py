"""Offline tests for the loopback guard. They need no emulator and never reach the network."""

import pytest

from emulator_guard import REQUIRED_HOSTS, emulator_endpoints

GOOD = {
    "FIRESTORE_EMULATOR_HOST": "127.0.0.1:8080",
    "FIREBASE_AUTH_EMULATOR_HOST": "localhost:9099",
    "STORAGE_EMULATOR_HOST": "http://[::1]:9199",
}


def with_value(name, value):
    return {**GOOD, name: value}


def test_the_three_variables_the_clients_read_are_the_required_set():
    assert REQUIRED_HOSTS == (
        "FIRESTORE_EMULATOR_HOST",
        "FIREBASE_AUTH_EMULATOR_HOST",
        "STORAGE_EMULATOR_HOST",
    )


def test_good_loopback_values_are_accepted():
    endpoints = emulator_endpoints(GOOD)
    assert endpoints == {
        "FIRESTORE_EMULATOR_HOST": ("127.0.0.1", 8080),
        "FIREBASE_AUTH_EMULATOR_HOST": ("localhost", 9099),
        "STORAGE_EMULATOR_HOST": ("::1", 9199),
    }


@pytest.mark.parametrize("name", REQUIRED_HOSTS)
def test_a_missing_variable_is_named(name):
    environ = {key: value for key, value in GOOD.items() if key != name}
    with pytest.raises(ValueError, match=name):
        emulator_endpoints(environ)


@pytest.mark.parametrize("name", REQUIRED_HOSTS)
@pytest.mark.parametrize("value", ["", "   "])
def test_an_empty_variable_counts_as_missing(name, value):
    with pytest.raises(ValueError, match=name):
        emulator_endpoints(with_value(name, value))


@pytest.mark.parametrize(
    "name, value",
    [
        ("FIRESTORE_EMULATOR_HOST", "127.0.0.1:9099@example.invalid:80"),
        ("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9099@example.invalid:80"),
        ("STORAGE_EMULATOR_HOST", "http://127.0.0.1:9099@example.invalid:80"),
        ("STORAGE_EMULATOR_HOST", "http://fireemu:secret@127.0.0.1:9199"),
        ("FIRESTORE_EMULATOR_HOST", "fireemu:secret@127.0.0.1:8080"),
    ],
)
def test_userinfo_is_rejected_without_echoing_the_value(name, value):
    with pytest.raises(ValueError) as caught:
        emulator_endpoints(with_value(name, value))
    assert name in str(caught.value)
    assert "secret" not in str(caught.value)
    assert value not in str(caught.value)


@pytest.mark.parametrize(
    "name, value",
    [
        ("FIRESTORE_EMULATOR_HOST", "example.invalid:8080"),
        ("FIREBASE_AUTH_EMULATOR_HOST", "10.0.0.5:9099"),
        ("FIREBASE_AUTH_EMULATOR_HOST", "0.0.0.0:9099"),
        ("FIRESTORE_EMULATOR_HOST", "firestore.googleapis.com:443"),
        ("STORAGE_EMULATOR_HOST", "http://storage.googleapis.com:443"),
        ("STORAGE_EMULATOR_HOST", "http://127.0.0.1.example.invalid:9199"),
        ("FIRESTORE_EMULATOR_HOST", "127.0.0.2:8080"),
    ],
)
def test_non_loopback_hosts_are_rejected(name, value):
    with pytest.raises(ValueError, match=name):
        emulator_endpoints(with_value(name, value))


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "127.0.0.1:",
        "127.0.0.1:abc",
        "127.0.0.1:+80",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "localhost:٨٠",
        "[::1]",
    ],
)
def test_a_non_numeric_or_out_of_range_port_is_rejected(value):
    with pytest.raises(ValueError, match="FIRESTORE_EMULATOR_HOST"):
        emulator_endpoints(with_value("FIRESTORE_EMULATOR_HOST", value))


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1:9199",
        "https://127.0.0.1:9199",
        "ftp://127.0.0.1:9199",
        "http://127.0.0.1",
    ],
)
def test_storage_must_be_an_http_url_with_a_loopback_port(value):
    with pytest.raises(ValueError, match="STORAGE_EMULATOR_HOST"):
        emulator_endpoints(with_value("STORAGE_EMULATOR_HOST", value))


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1:8080/extra",
        "127.0.0.1:8080?x=1",
        "127.0.0.1:8080#frag",
    ],
)
def test_a_path_query_or_fragment_is_rejected(value):
    with pytest.raises(ValueError, match="FIRESTORE_EMULATOR_HOST"):
        emulator_endpoints(with_value("FIRESTORE_EMULATOR_HOST", value))
