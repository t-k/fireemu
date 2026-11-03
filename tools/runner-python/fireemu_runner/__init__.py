"""The fireemu runner for Python Functions codebases (see docs/specifications and the design memo).

The daemon speaks to a runner over its stdin and stdout with length-prefixed JSON frames. This
package is imported by `runner.py`, which sits beside it.
"""
