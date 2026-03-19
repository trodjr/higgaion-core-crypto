package higgaion

/*
#cgo CFLAGS: -I../include/higgaion
#cgo LDFLAGS: -L../obj -l:pqc_crypto.o -lcrypto
#include <stdlib.h>
#include "pqc_crypto.h"

// HIG-003: expose up-ref via cgo for safe pointer sharing
static inline int cgo_key_up_ref(HiggaionKey *dst, const HiggaionKey *src) {
    return higgaion_key_up_ref(dst, src);
}
*/
import "C"
import (
	"errors"
	"unsafe"
)

// Error Definitions
var (
	ErrKeyGeneration = errors.New("failed to generate PQC keypair")
	ErrSigning       = errors.New("failed to sign message")
	ErrVerification  = errors.New("signature verification failed")
	ErrNoMemory      = errors.New("failed to allocate memory")
	ErrInvalidParam  = errors.New("invalid parameter")
)

// PrivateKey represents a Higgaion mathematically verified ML-DSA or ML-KEM private key.
type PrivateKey struct {
	inner C.HiggaionKey
}

// PublicKey represents a Higgaion PQC public key.
type PublicKey struct {
	inner C.HiggaionKey
}

// GenerateKeypair securely generates a new Post-Quantum keypair (e.g. "ML-DSA-87").
// IMPORTANT: The caller must explicitly call Free() on the returned keys to prevent memory leaks!
func GenerateKeypair(algName string) (*PrivateKey, *PublicKey, error) {
	var priv PrivateKey
	var pub PublicKey

	C.higgaion_key_init(&priv.inner)
	C.higgaion_key_init(&pub.inner)

	cAlgName := C.CString(algName)
	defer C.free(unsafe.Pointer(cAlgName))

	// In the open core C implementation, generate_keypair populates a single HiggaionKey with the EVP_PKEY
	// The open core library actually stores both public and private in the same EVP_PKEY struct.
	// For the Go idiomatic wrapper, we generate it into the private key, and for the public key
	// we will logically use the exact same underlying OpenSSL reference for now, but in reality 
	// they should be separated if exported. We will structure it exactly as the C API expects.
	C.generate_keypair(&priv.inner, cAlgName)

	if priv.inner.pkey == nil {
		return nil, nil, ErrKeyGeneration
	}

	// HIG-003 FIX: Up-ref the EVP_PKEY so the public key holds an independent
	// reference.  Both priv and pub can now be freed independently without
	// triggering use-after-free or double-free.
	if C.cgo_key_up_ref(&pub.inner, &priv.inner) != 1 {
		// Up-ref failed — clean up and report error
		C.higgaion_key_free(&priv.inner)
		return nil, nil, ErrKeyGeneration
	}

	return &priv, &pub, nil
}

// Free explicitly destructs the underlying OpenSSL memory structures.
// Must be called using `defer priv.Free()` immediately after generation.
func (k *PrivateKey) Free() {
	if k.inner.pkey != nil {
		C.higgaion_key_free(&k.inner)
		k.inner.pkey = nil
	}
}

// Free explicitly destructs the underlying OpenSSL memory structures for the
// public key.  HIG-003 FIX: PublicKey now holds an independent EVP_PKEY
// reference and must be freed separately from PrivateKey.
func (k *PublicKey) Free() {
	if k.inner.pkey != nil {
		C.higgaion_key_free(&k.inner)
		k.inner.pkey = nil
	}
}

// Sign delegates the domain-separated signing protocol to the native C proxy.
func (k *PrivateKey) Sign(message []byte, domain string) ([]byte, error) {
	if k.inner.pkey == nil {
		return nil, ErrInvalidParam
	}

	var cSig *C.uint8_t
	var cSigLen C.size_t

	var cMsg *C.uint8_t
	var cMsgLen C.size_t
	if len(message) > 0 {
		cMsg = (*C.uint8_t)(unsafe.Pointer(&message[0]))
		cMsgLen = C.size_t(len(message))
	}

	cDomain := C.CString(domain)
	defer C.free(unsafe.Pointer(cDomain))

	C.pqc_sign(&cSig, &cSigLen, cMsg, cMsgLen, cDomain, &k.inner)

	if cSig == nil || cSigLen == 0 {
		return nil, ErrSigning
	}

	// Convert the raw C byte array back to a garbage-collected Go slice
	goSig := C.GoBytes(unsafe.Pointer(cSig), C.int(cSigLen))

	// IMPORTANT: Free the memory allocated by the C malloc inside pqc_sign!
	C.free(unsafe.Pointer(cSig))

	return goSig, nil
}

// Verify mathematically verifies the domain-separated signature against the Open-Core C primitives.
func (k *PublicKey) Verify(message []byte, signature []byte, domain string) bool {
	if k.inner.pkey == nil || len(signature) == 0 {
		return false
	}

	var cMsg *C.uint8_t
	var cMsgLen C.size_t
	if len(message) > 0 {
		cMsg = (*C.uint8_t)(unsafe.Pointer(&message[0]))
		cMsgLen = C.size_t(len(message))
	}

	cSig := (*C.uint8_t)(unsafe.Pointer(&signature[0]))
	cSigLen := C.size_t(len(signature))

	cDomain := C.CString(domain)
	defer C.free(unsafe.Pointer(cDomain))

	valid := C.pqc_verify(cMsg, cMsgLen, cSig, cSigLen, cDomain, &k.inner)

	return bool(valid)
}
