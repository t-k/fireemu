"""Static safety boundaries supplement the opt-in real-process flow."""

import ast
from pathlib import Path


def test_recorder_has_no_update_or_bulk_account_operation():
    path = Path(__file__).with_name("deleted_recorder.py")
    assert path.exists()
    tree = ast.parse(path.read_text())
    text = ast.unparse(tree).replace("'", '"')
    assert 'client("delete", {"idToken": target["fixed"]["idToken"]})' in text
    assert 'core.recovery_identity(target["journal"])' in text
    assert 'admin("lookup", {"localId": [target["uid"]]})' in text
    assert 'admin("lookup", {"email": [target["email"]]})' in text
    assert "revoke" not in text
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"admin", "client"}
        ):
            assert isinstance(node.args[0], ast.Constant)
            assert node.args[0].value in {
                "lookup",
                "delete",
                "signUp",
                "signInWithPassword",
            }
