"""Shared fixtures for the Python Admin SDK smoke suite.

The suite runs under `fireemu exec`, which exports the emulator hosts the clients read (see
emulator_guard.py). It never contacts Google: every client is pointed at the emulator by those
variables, and the guard refuses to start unless each one is a loopback address.
"""

import os
import uuid

import firebase_admin
import pytest
from firebase_admin import credentials
from google.auth.credentials import AnonymousCredentials

from emulator_guard import emulator_endpoints

PROJECT = os.environ.get("GOOGLE_CLOUD_PROJECT", "demo-app")


def pytest_configure(config):
    try:
        emulator_endpoints(os.environ)
    except ValueError as error:
        raise pytest.UsageError(str(error)) from error


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
