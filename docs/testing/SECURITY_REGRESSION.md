# Security regression

`make safe-policy` (`tests/safe-policy/run-demo.sh`) must pass after every policy or compatibility change.

Method: an intentionally vulnerable app is attacked identically bare (control) and under the corrected policy. Effects are checked, not logs: marker file absent, secret not in the response, lab listener hit count 0. If the control arm does not reproduce all four attacks the run fails, because a "denied" result would prove nothing.

Also asserted: the natural `exec.allow: [/usr/bin/ping]` is rejected as unenforceable; an unsafe candidate is not promoted over the active policy (scenario 6 simulates promotion in shell; it is not the product's rollback path).

Unit test: `engine/policy/execgrant_test.go`. Synthetic data only; all targets are loopback.
