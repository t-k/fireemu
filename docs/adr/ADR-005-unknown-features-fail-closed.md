# ADR-005: Unknown features fail closed

- Status: accepted (2026-08-29)

## Decision

Operations whose production behaviour cannot be verified are rejected with `UNIMPLEMENTED` or
`FAILED_PRECONDITION`, never silently accepted or degraded. This applies to Query operators,
Pipeline stages (including `update(...)` / `delete()` output stages), Text Search without a
READY index, Rules built-ins and limit calculations. Missing enforcement is declared in the
Capability Manifest as `unsupported`, never treated as "no problem".
