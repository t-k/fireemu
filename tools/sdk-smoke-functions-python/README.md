# Python Functions fixture

A Python Functions codebase (`main.py`) and its hash-locked requirements, used by the tests of
`tools/runner-python` and by the `functions-python` CI job. The SDK is `firebase-functions` 0.6.0.

```sh
python3.12 -m venv venv
venv/bin/pip install --require-hashes -r requirements.txt
```

`requirements.txt` is generated from `requirements.in` with
`uv pip compile requirements.in --python-version 3.12 --generate-hashes -o requirements.txt`.
