# ADR 002: Injectable clock for all time-dependent code

## Status
Accepted

## Context
Expiry, overlap windows, and token lifetimes are time-dependent. Testing
them with wall-clock time needs sleeps (slow, flaky) or mocking internals
(brittle).

## Decision
Every time-sensitive class takes a `clock` with a `now()` method.
Production passes `Clock()` (wall time); tests pass `FakeClock()` and
advance it explicitly. No `datetime.now()` calls inside library code.

## Consequences
- Expiry tests are deterministic and instant (e.g. "advance 2 hours, assert
  expired").
- Demos can use `FakeClock` for reproducible output.
- Small API cost: one extra constructor argument everywhere.
