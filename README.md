# Bounty #8 — Local nonce-bound `personal_sign` regression lab

UUID: `80c238e8-dd8c-4d0a-8f60-711142f1a496`

This is a deterministic, local-only security regression artifact. It uses synthetic wallets derived from fixed seeds and a pure-Python secp256k1/Keccak implementation; it never contacts a chain, service, wallet, or third party.

## Run

```bash
cd /root/imdworks-work/wallet-signin-regression
PYTHONPATH=. python3 -m unittest discover -s tests -v
PYTHONPATH=. python3 run_bounty8.py | tee traces/final-run.log
```

The runner writes `reports/final-report.json` and `traces/final-trace.json`. It covers 30 deterministic cases, including replay, wrong signer, origin confusion, expiry equal/past boundaries, malformed signatures, message tampering, nonce formats, two deliberately vulnerable baselines, and 32 concurrent attempts against one nonce. The raw concurrent outcomes are checked for exactly one `accepted` and 31 `rejected:nonce-consumed` results, then sorted before persistence so scheduler order cannot alter evidence hashes.

## Security contract

A valid request signs an exact structured message containing address, nonce, HTTPS origin, and expiry. Verification recovers the signer from the Ethereum personal-sign digest, compares the recovered address to the message address, checks the exact expected origin and `now <= expiry`, and atomically consumes `(address, nonce)` under a lock. The atomic check-and-consume is what makes concurrent replay one-success-only.

## Scope and non-goals

This is a teaching/regression harness, not production key custody or an HTTP deployment. The service boundary is represented by `ConcurrentSigninService`; all state is in memory. Production systems must add transport protections, TLS, rate limiting, persistent nonce storage, session binding, and operational monitoring.
