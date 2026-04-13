package higgaion

import (
	"strings"
	"testing"
)

func TestPQCSigningAndVerification(t *testing.T) {
	// Generate the mathematically verified ML-DSA-87 keypair
	priv, pub, err := GenerateKeypair("ML-DSA-87")
	if err != nil {
		priv, pub, err = GenerateKeypair("ED25519")
		if err != nil {
			t.Fatalf("Failed to generate PQC keypair: %v", err)
		}
	}

	// Defer memory freeing to prevent OpenSSL pointer leaks
	defer priv.Free()

	// 1. Valid Signature Test
	message := []byte("authorization_payload_12345")
	domain := "gateway-production-zone"

	sig, err := priv.Sign(message, domain)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Signature was empty")
	}

	valid := pub.Verify(message, sig, domain)
	if !valid {
		t.Error("Mathematically valid signature was incorrectly rejected")
	}

	// 2. Invalid Domain-Separation Attack Test
	invalidDomain := "gateway-staging-zone"
	valid = pub.Verify(message, sig, invalidDomain)
	if valid {
		t.Error("Signature verification completely failed domain-separation check! Cryptographic invariant broken.")
	}

	// 3. Invalid Message Modification Test
	tamperedMessage := []byte("authorization_payload_12346")
	valid = pub.Verify(tamperedMessage, sig, domain)
	if valid {
		t.Error("Signature verification allowed a modified message payload!")
	}
}

func TestNilMessageSigning(t *testing.T) {
	priv, pub, err := GenerateKeypair("ML-DSA-87")
	if err != nil {
		priv, pub, err = GenerateKeypair("ED25519")
		if err != nil {
			t.Fatalf("Failed to generate PQC keypair: %v", err)
		}
	}
	defer priv.Free()

	domain := "empty-payload-test"
	sig, err := priv.Sign(nil, domain)
	if err != nil {
		t.Fatalf("Failed to sign nil message: %v", err)
	}

	if !pub.Verify(nil, sig, domain) {
		t.Error("Failed to verify signature for nil message")
	}
}

func TestDomainSeparationPrefixCollisionResistance(t *testing.T) {
	priv, pub, err := GenerateKeypair("ML-DSA-87")
	if err != nil {
		priv, pub, err = GenerateKeypair("ED25519")
		if err != nil {
			t.Fatalf("Failed to generate keypair: %v", err)
		}
	}
	defer priv.Free()

	// Old broken construction: ("A","BC") == ("AB","C") if using raw concatenation.
	sig, err := priv.Sign([]byte("BC"), "A")
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	if pub.Verify([]byte("C"), sig, "AB") {
		t.Fatal("Domain separation failed: prefix-collision verified across domains/messages")
	}
}

func TestOverlongDomainRejected(t *testing.T) {
	priv, _, err := GenerateKeypair("ML-DSA-87")
	if err != nil {
		priv, _, err = GenerateKeypair("ED25519")
		if err != nil {
			t.Fatalf("Failed to generate keypair: %v", err)
		}
	}
	defer priv.Free()

	longDomain := strings.Repeat("A", 4096) + "B" // 4097 bytes
	_, err = priv.Sign([]byte("payload"), longDomain)
	if err == nil {
		t.Fatal("Expected signing to fail for overlong domain tag, but it succeeded")
	}
}
