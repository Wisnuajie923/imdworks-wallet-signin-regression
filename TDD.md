# TDD evidence

The implementation was developed with a strict RED/GREEN loop.

1. `tests/test_signin.py` was authored before `signin.py`.
2. RED was executed with the implementation absent; it failed because `signin` could not be imported. Evidence: `traces/tdd-red.log` (exit 1).
3. Minimal implementation was added.
4. GREEN was executed; an origin-empty fixture bug was exposed and corrected, then the focused suite passed. Evidence: `traces/tdd-green.log` (exit 0, 6 tests).
5. The final runner adds deterministic adversarial acceptance coverage and concurrency evidence.
6. Bounty #8 regression: the first determinism test run was RED because `canonicalize_evidence_results` was absent (`traces/tdd-red-determinism.log`, exit 1). The helper was added, raw concurrency counts remain asserted at exactly 1 accepted and 31 nonce-consumed, and only persisted evidence is sorted. GREEN passed all 7 focused tests (`traces/tdd-green-determinism.log`, exit 0).
7. Five fresh runner executions produced byte-identical report and trace artifacts; see `traces/final-run.log` and the final hashes from the acceptance run.

Commands:

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -v
PYTHONPATH=. python3 run_bounty8.py
```
