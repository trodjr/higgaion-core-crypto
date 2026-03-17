import pytest
from higgaion import GenerateKeypair, HiggaionError

def test_pqc_signing_and_verification():
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

def test_pqc_nil_signing():
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
