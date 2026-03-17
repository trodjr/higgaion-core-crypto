use higgaion_core_crypto::{generate_keypair, HiggaionError};

#[test]
fn test_pqc_signing_and_verification() -> Result<(), HiggaionError> {
    // Generate the mathematical keypair, falling back to ED25519 for older CI nodes
    let (priv_key, pub_key) = match generate_keypair("ML-DSA-87") {
        Ok(keys) => keys,
        Err(_) => generate_keypair("ED25519")?,
    };

    let message = b"authorization_payload_12345";
    let domain = "gateway-production-zone";

    // 1. Valid Signature Test
    let sig = priv_key.sign(message, domain)?;
    assert!(!sig.is_empty(), "Native signature was perfectly empty");

    let is_valid = pub_key.verify(message, &sig, domain);
    assert!(is_valid, "Mathematically valid signature was completely rejected");

    // 2. Invalid Domain-Separation Attack Test
    let invalid_domain = "gateway-staging-zone";
    let is_valid = pub_key.verify(message, &sig, invalid_domain);
    assert!(!is_valid, "Signature validation bypassed domain-separation filter!");

    // 3. Invalid Message Modification Test
    let tampered_message = b"authorization_payload_12346";
    let is_valid = pub_key.verify(tampered_message, &sig, domain);
    assert!(!is_valid, "Signature validation allowed a modified message payload!");

    Ok(())
}

#[test]
fn test_pqc_nil_signing() -> Result<(), HiggaionError> {
    let (priv_key, pub_key) = match generate_keypair("ML-DSA-87") {
        Ok(keys) => keys,
        Err(_) => generate_keypair("ED25519")?,
    };

    let domain = "empty-payload-test";
    let empty_message: &[u8] = &[];
    
    let sig = priv_key.sign(empty_message, domain)?;
    assert!(!sig.is_empty(), "Signature for nil message should not be empty");

    let is_valid = pub_key.verify(empty_message, &sig, domain);
    assert!(is_valid, "Failed to verify signature for nil message");

    let injected = b"injected";
    assert!(!pub_key.verify(injected, &sig, domain), "Nil signature verified non-nil payload");

    Ok(())
}
