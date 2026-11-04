"""Turning a failure into text without trusting the failure.

An exception raised by user code can run user code when it is turned into text (`__str__`, `__repr__`, a
chained cause). With one process environment shared by every invocation, that text must be made while the
failing invocation still holds its place in the secret gate, and a failure to make it must not lose the result.
"""

import inspect
import traceback


def describe(error: BaseException) -> tuple[str, str]:
    """`(traceback text, short text)` of `error`; never raises, whatever the error's methods do."""
    try:
        diagnostic = "".join(traceback.format_exception(error))
    except BaseException:
        diagnostic = f"{type(error).__name__}: (the error could not be formatted)\n"
    try:
        text = str(error) or type(error).__name__
    except BaseException:
        text = type(error).__name__
    return diagnostic, text


ASYNC_HANDLER = (
    "the function is an async handler: the Python SDK never awaits a handler, so its body would never run "
    "(production skips it silently); declare it with def"
)


def is_async_handler(function) -> bool:
    """Whether the user's function behind an SDK wrapper is a coroutine function."""
    try:
        return inspect.iscoroutinefunction(inspect.unwrap(function))
    except ValueError:  # a cycle of __wrapped__ links: not something this can decide
        return False
