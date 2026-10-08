# Threat model

## Assets

- Authentication decision and session issuance.
- Per-wallet nonce uniqueness.
- Origin/domain binding of a signed login intent.

## Trust boundaries

1. Synthetic wallet signer (trusted only to produce signatures).
2. Untrusted message/signature/origin input to the verifier.
3. Concurrent callers racing the same signed request.
4. In-memory verifier state (trusted implementation, not durable storage).

## Adversaries and mitigations

| Adversary | Attempt | Mitigation |
|---|---|---|
| Replay attacker | Re-submit an accepted signature | Atomic `(address, nonce)` consumption |
| Wrong wallet | Sign the same text with another key | secp256k1 public-key recovery and address comparison |
| Origin attacker | Alter or omit origin / use lookalike host | Exact HTTPS origin grammar and equality check |
| Time attacker | Use an expired token or boundary value | deterministic `now <= expires` policy |
| Parser attacker | Truncate, extend, or corrupt signature/message | strict message grammar, 65-byte signature and r/s/v bounds |
| Race attacker | Submit the same nonce in 32 simultaneous calls | lock encloses check and consume |

## Deliberately vulnerable baselines

- `VulnerableNoNonce` resets its consumption state on every verification, proving replay succeeds.
- `VulnerableOrigin` trusts the origin inside the signed text instead of the server-expected origin, proving origin bypass.

The runner records these as expected vulnerability demonstrations; they are not used as the secure implementation.

## Residual risk

The lab has no durable nonce store, HTTP/TLS layer, CSRF/session policy, key custody, rate limits, or cross-process lock. These are explicitly outside the local bounty acceptance scope and must be addressed before production use.
