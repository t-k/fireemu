# fireemu Python runner

`runner.py` is the process the daemon starts for a Python Functions codebase, with the interpreter of
the codebase's `venv`. It speaks the same length-prefixed JSON frames on stdin and stdout as the Node
runner (`tools/runner-node`), serves `onRequest` and `onCall` functions on a loopback HTTP server, and
turns a Firestore event into the CloudEvent the Python SDK expects. The package is `fireemu_runner/`;
the design memo is the reference for why (one process per codebase, protobuf for Firestore events).

## Tests

The tests use the real `firebase-functions` SDK, hash-locked in the fixture codebase
`tools/sdk-smoke-functions-python` (its `README.md` shows how to create the virtual environment).

```sh
tools/sdk-smoke-functions-python/venv/bin/python -m pytest -p no:cacheprovider tools/runner-python/tests
```

Some tests start the runner as a process (`harness.py`); the rest call the router, the dispatcher and the
serve loop in process, so that mutation testing sees them.

## Mutation testing

[mutmut](https://github.com/boxed/mutmut) 3.8.1 (chosen over cosmic-ray, pytest-gremlins, mutatest and
MutPy; see the design memo, question 10) is pinned with hashes in `requirements-mutation.txt`, which is
the SDK lock of the fixture plus mutmut:

```sh
python3 -m venv /tmp/runner-mutation
/tmp/runner-mutation/bin/pip install --require-hashes -r tools/runner-python/requirements-mutation.txt
cd tools/runner-python
/tmp/runner-mutation/bin/mutmut run          # results: mutants/, readable with `mutmut results --all true`
```

`pyproject.toml` configures it. mutmut first runs the tests clean and once with a forced failure (the
control that proves a failing mutant is noticed), then one mutant at a time. The tests start the runner
as a subprocess, so the harness passes `MUTANT_UNDER_TEST` to it. Do not edit `fireemu_runner/` during a
run: mutmut mutates a copy (`mutants/`), but its test selection is built from the first pass.

The last run (mutmut 3.8.1, Python 3.12, 1,282 mutants of `fireemu_runner/`): 1,223 killed, 38 more ended
in a hang, 21 survived. The survivors are equivalent or immaterial (a codec alias such as `"UTF-8"`,
`ensure_ascii=None`, a Flask endpoint name derived from the view function, an unbuffered versus buffered
stream that is flushed after each frame, the digit counter of the frame header whose bound the length cap
already enforces, the case of a header name) or are killed by a process-level test that mutmut's test
selection does not see (the two `_QuietHandler` mutants: `test_the_http_server_logs_no_request_lines_on_stderr`).
