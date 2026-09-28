"""An early pair abort is retained as an incomplete parent recording."""

import json

import pytest
import second_mapped


@pytest.mark.parametrize(
    "failed_check",
    ["safety", "cleanupComplete", "recordingComplete"],
)
def test_child_saves_incomplete_cases_when_pair_skips_mapped(
    tmp_path, monkeypatch, failed_check
):
    output = tmp_path
    (output / "manifest.json").write_text(
        json.dumps(
            {
                "artifactSha256": "a" * 64,
                "executionCommit": "b" * 40,
                "configurationDigest": "c" * 64,
            }
        )
    )
    monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9099")
    monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:8080")
    monkeypatch.setenv("FIREEMU_CONTROL_URL", "http://127.0.0.1:9000")
    monkeypatch.setenv("FIREEMU_CONTROL_TOKEN", "local-token")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", second_mapped.PROJECT)
    monkeypatch.setattr(
        second_mapped,
        "local_addresses",
        lambda fs, control: ("http://" + fs, control),
    )
    monkeypatch.setattr(
        second_mapped,
        "control_get",
        lambda _control, _path, token: (
            (200, {"project": second_mapped.PROJECT})
            if token == "local-token"
            else (403, {})
        ),
    )

    direct = {
        "mode": "direct",
        "rows": [{"id": "second45/direct-evidence"}],
        "recordingComplete": True,
        "cleanupComplete": True,
        "safety": True,
    }
    direct[failed_check] = False
    comparison = {
        "rows": [],
        "direct": direct,
        "mapped": {
            "mode": "mapped",
            "rows": [],
            "recordingComplete": False,
            "cleanupComplete": True,
            "safety": None,
            "skipReason": "direct incomplete, safety violation, or unconfirmed cleanup",
        },
        "recordingComplete": False,
        "safety": direct["safety"],
        "mapping": "indeterminate",
    }

    def abort_pair(_local, pair_output, _identity):
        pair_output.mkdir(parents=True)
        (pair_output / "direct").mkdir()
        (pair_output / "direct" / "result.json").write_text(json.dumps(direct))
        second_mapped.save(pair_output / "comparison.json", comparison)
        return comparison

    monkeypatch.setattr(second_mapped, "run_pair", abort_pair)

    with pytest.raises(ValueError, match="second45 incomplete"):
        second_mapped.child(output, "nonce")

    cases = json.loads((output / "cases.json").read_text())
    assert cases["recordingComplete"] is False
    assert cases["stateValidation"] is False
    assert cases["cases"][0]["status"] == "indeterminate"
    assert cases["localObservations"]["comparison"] == comparison
    assert not (output / "pair" / "mapped" / "result.json").exists()
