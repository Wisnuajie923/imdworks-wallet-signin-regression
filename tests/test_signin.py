import unittest

from signin import (
    SecureVerifier, VulnerableNoNonce, VulnerableOrigin, Wallet,
    build_message, ConcurrentSigninService, VerifyError,
    canonicalize_evidence_results,
)


class SigninSecurityTests(unittest.TestCase):
    def setUp(self):
        self.alice = Wallet.from_seed("alice")
        self.bob = Wallet.from_seed("bob")
        self.origin = "https://app.local"

    def signed(self, wallet=None, nonce="n-001", origin=None, expires=2000):
        wallet = wallet or self.alice
        origin = self.origin if origin is None else origin
        msg = build_message(wallet.address, nonce, origin, expires)
        return wallet, msg, wallet.sign_personal(msg)

    def test_happy_path_and_nonce_consumption(self):
        v = SecureVerifier(clock=lambda: 1000)
        _, msg, sig = self.signed()
        self.assertTrue(v.verify(msg, sig, expected_origin=self.origin))
        with self.assertRaises(VerifyError): v.verify(msg, sig, expected_origin=self.origin)

    def test_wrong_signer_rejected(self):
        v = SecureVerifier(clock=lambda: 1000); _, msg, sig = self.signed()
        with self.assertRaises(VerifyError): v.verify(msg, self.bob.sign_personal(msg), expected_origin=self.origin)

    def test_origin_expiry_and_boundaries(self):
        for bad_origin in ("https://evil.local", "https://app.local.evil", "http://app.local", ""):
            v = SecureVerifier(clock=lambda: 1000); _, msg, sig = self.signed(origin=bad_origin)
            with self.assertRaises(VerifyError): v.verify(msg, sig, expected_origin=self.origin)
        v = SecureVerifier(clock=lambda: 2000); _, msg, sig = self.signed(expires=2000)
        self.assertTrue(v.verify(msg, sig, expected_origin=self.origin))
        v = SecureVerifier(clock=lambda: 2001); _, msg, sig = self.signed(expires=2000)
        with self.assertRaises(VerifyError): v.verify(msg, sig, expected_origin=self.origin)

    def test_malformed_signatures_rejected(self):
        v = SecureVerifier(clock=lambda: 1000); _, msg, sig = self.signed()
        bad = [b"", b"x" * 64, sig[:-1], bytes([sig[0] ^ 1]) + sig[1:], sig[:32] + b"\0" * 32 + sig[64:], sig[:64] + b"\xff"]
        for candidate in bad:
            with self.assertRaises(VerifyError): v.verify(msg, candidate, expected_origin=self.origin)

    def test_concurrent_exactly_one_success(self):
        s = ConcurrentSigninService(clock=lambda: 1000)
        _, msg, sig = self.signed()
        results = s.concurrent_attempts(msg, sig, self.origin, count=32)
        self.assertEqual(results.count("accepted"), 1)
        self.assertEqual(results.count("rejected:nonce-consumed"), 31)

    def test_evidence_results_have_canonical_order(self):
        raw = ["rejected:nonce-consumed", "accepted", "rejected:nonce-consumed"]
        self.assertEqual(
            canonicalize_evidence_results(raw),
            ["accepted", "rejected:nonce-consumed", "rejected:nonce-consumed"],
        )

    def test_vulnerable_baselines_are_rejected_by_security_suite(self):
        _, msg, sig = self.signed()
        self.assertTrue(VulnerableNoNonce(clock=lambda: 1000).verify(msg, sig, expected_origin=self.origin))
        self.assertTrue(VulnerableOrigin(clock=lambda: 1000).verify(msg, sig, expected_origin=self.origin))


if __name__ == "__main__": unittest.main()
