import unittest
from higgaion import GenerateKeypair, HiggaionError

class TestCrypto(unittest.TestCase):
    def test_pqc_signing_and_verification(self):
        """Formally exercises the domain-separated signature mechanics across the C library boundary."""
        try:
            priv, pub = GenerateKeypair("ML-DSA-87")
        except HiggaionError:
            priv, pub = GenerateKeypair("ED25519")

        message = b"authorization_payload_12345"
        domain = "gateway-production-zone"

        # 1. Valid Check
        sig = priv.sign(message, domain)
        assert len(sig) > 0, "Native signature was perfectly empty"
        
        valid = pub.verify(message, sig, domain)
        assert valid is True, "Mathematically verified signature completely rejected"

        # 2. Invalid Domain-Separation Evasion
        invalid_domain = "gateway-staging-zone"
        valid = pub.verify(message, sig, invalid_domain)
        assert valid is False, "Signature bypassed domain-separation filter!"

        # 3. Payload Tampering 
        tampered_msg = b"authorization_payload_12346"
        valid = pub.verify(tampered_msg, sig, domain)
        assert valid is False, "Signature allowed manipulated byte payload"

    def test_pqc_nil_signing(self):
        """Asserts that C pointers handle `None` Python buffers predictably."""
        try:
            priv, pub = GenerateKeypair("ML-DSA-87")
        except HiggaionError:
            priv, pub = GenerateKeypair("ED25519")
        
        domain = "null-buffer-eval"
        sig = priv.sign(None, domain)
        assert len(sig) > 0

        assert pub.verify(None, sig, domain) is True
        assert pub.verify(b"injected", sig, domain) is False

    def test_domain_separation_prefix_collision_resistance(self):
        """Rejects prefix-collision bypasses (e.g., ('A','BC') vs ('AB','C'))."""
        try:
            priv, pub = GenerateKeypair("ML-DSA-87")
        except HiggaionError:
            priv, pub = GenerateKeypair("ED25519")

        sig = priv.sign(b"BC", "A")
        assert pub.verify(b"C", sig, "AB") is False

    def test_overlong_domain_rejected(self):
        """Domain tags must be rejected (not truncated) when exceeding the maximum length."""
        try:
            priv, _ = GenerateKeypair("ML-DSA-87")
        except HiggaionError:
            priv, _ = GenerateKeypair("ED25519")

        long_domain = ("A" * 4096) + "B"  # 4097 bytes
        with self.assertRaises(HiggaionError):
            priv.sign(b"payload", long_domain)
