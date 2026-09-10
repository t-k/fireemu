"""Exact supplementary-character inputs, not inferred lengths."""

import pytest
from boundary_contract import CASES, generate, input_shape


def test_three_exact_shapes_and_invalid_variants():
    expected = [(2064, 8157, 4095), (2064, 8160, 4096), (2065, 8161, 4097)]
    for name, (scalars, byte_count, units) in zip(CASES, expected, strict=True):
        value = generate(name)
        assert input_shape(name, value) == {
            "scalars": scalars,
            "utf8Bytes": byte_count,
            "utf16Units": units,
        }
        for invalid in (value + "a", value[:-1], "!" + value[1:], "a" * units):
            with pytest.raises(ValueError):
                input_shape(name, invalid)
