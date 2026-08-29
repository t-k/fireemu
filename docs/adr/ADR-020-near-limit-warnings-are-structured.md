# ADR-020: Near-limit warnings are structured diagnostics

- Status: accepted (2026-08-29)

## Decision

Capacity limits emit `notice` (75%), `warning` (85%) and `critical` (95%) diagnostics with a
stable code, the limit ID, current / maximum / unit, precision and a remediation code. The
boundary check runs first: an inclusive maximum allows N with a critical warning; an exclusive
maximum rejects N. Ratios are compared with checked integer arithmetic in basis points, never
floating point, so that the first firing value is exactly `ceil(maximum * threshold)`.
