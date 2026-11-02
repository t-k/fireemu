"""Shared fixtures for the Python Admin SDK smoke suite.

The suite runs under `fireemu exec`, which exports FIRESTORE_EMULATOR_HOST,
FIREBASE_AUTH_EMULATOR_HOST and FIREBASE_STORAGE_EMULATOR_HOST to the command. It never
contacts Google: every client is pointed at the emulator by those variables.
"""

import os
import uuid

import firebase_admin
import pytest
from firebase_admin import credentials
from google.auth.credentials import AnonymousCredentials

PROJECT = os.environ.get("GOOGLE_CLOUD_PROJECT", "demo-app")
REQUIRED_HOSTS = (
    "FIRESTORE_EMULATOR_HOST",
    "FIREBASE_AUTH_EMULATOR_HOST",
    "FIREBASE_STORAGE_EMULATOR_HOST",
)


def pytest_configure(config):
    missing = [name for name in REQUIRED_HOSTS if not os.environ.get(name)]
    if missing:
        raise pytest.UsageError(
            "run this suite under `fireemu exec` (missing " + ", ".join(missing) + ")"
        )
    for name in REQUIRED_HOSTS:
        host = os.environ[name].removeprefix("http://")
        if not host.startswith(("127.0.0.1:", "localhost:", "[::1]:")):
            raise pytest.UsageError(f"{name}={host} is not a loopback emulator")


class EmulatorCredential(credentials.Base):
    """No credential: the emulators need none, and this suite must never find real ones.

    Without it, initialize_app() falls back to Application Default Credentials, which a CI
    runner does not have (and a developer machine might, pointing at a real project).
    """

    def get_credential(self):
        return AnonymousCredentials()


@pytest.fixture(scope="session")
def app():
    app = firebase_admin.initialize_app(
        EmulatorCredential(),
        options={"projectId": PROJECT, "storageBucket": f"{PROJECT}.appspot.com"},
    )
    yield app
    firebase_admin.delete_app(app)


@pytest.fixture
def unique():
    """A short identifier that keeps one test's documents, users and objects apart."""
    return uuid.uuid4().hex[:12]
