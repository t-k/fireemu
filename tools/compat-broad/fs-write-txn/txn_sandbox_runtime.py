"""Explicit interpreter admission before any sandbox credential or request."""

import hashlib
import sys

PYTHON_VERSION = "3.12.13"


def require_minimum():
    if sys.version_info[:2] < (3, 12):
        raise ValueError("Python 3.12 or newer is required before sandbox admission")


def require_packet_runtime(version):
    require_minimum()
    actual = ".".join(str(part) for part in sys.version_info[:3])
    if version != PYTHON_VERSION or actual != version:
        raise ValueError("packet runtime must match the reviewed Python 3.12.13 exactly")


def evidence():
    return {
        "pythonVersion": ".".join(str(part) for part in sys.version_info[:3]),
        "pythonSysVersion": sys.version,
        "pythonExecutable": sys.executable,
    }


def public_evidence():
    """Bind the actual executable without publishing an operator's filesystem path."""
    return {
        "pythonVersion": ".".join(str(part) for part in sys.version_info[:3]),
        "pythonSysVersion": sys.version,
        "pythonExecutableSha256": hashlib.sha256(sys.executable.encode()).hexdigest(),
    }
