/**
 * @file pqc_crypto.h
 * @brief PQC cryptographic primitives for the migration engine.
 *
 * Provides ML-DSA OpenSSL wrappers and utility functions for
 * the isolated PQC verification module.
 */
#ifndef PQC_CRYPTO_H
#define PQC_CRYPTO_H

#include "pqc_types.h"
#include <openssl/x509.h>

/* ── Domain separation limits ───────────────────────────────────────── */

/**
 * Maximum domain separation tag length (bytes, excluding NUL terminator).
 *
 * Domain separation tags longer than this limit MUST be rejected by the
 * implementation (not truncated), to avoid cross-domain confusion.
 */
#define HIGGAION_DOMAIN_MAX_LEN 4096

/* ── Key lifecycle ───────────────────────────────────────────────────── */

/** Initialize a HiggaionKey to safe defaults (pkey = NULL). */
void higgaion_key_init(HiggaionKey *key);

/** Free internal resources of a HiggaionKey. */
void higgaion_key_free(HiggaionKey *key);

/** Monotonically erase the classical private key while enforcing ERASING/ERASED durable WAL markers. */
bool higgaion_key_erase_durable(HiggaionKey *key, const char *wal_path);

/**
 * Safely share an EVP_PKEY between two HiggaionKey structs by incrementing
 * the OpenSSL reference count (EVP_PKEY_up_ref).  Returns 1 on success, 0
 * on failure.  Both dst and src become independent owners that can be freed
 * separately via higgaion_key_free().
 *
 * HIG-003 mitigation: prevents use-after-free / double-free when FFI
 * wrappers hold both a PrivateKey and PublicKey referencing the same EVP_PKEY.
 */
int higgaion_key_up_ref(HiggaionKey *dst, const HiggaionKey *src);

/** Generate an ML-DSA-87 or ML-KEM-1024 keypair via OpenSSL EVP.
 *
 *  HIG-002: In production builds (HIGGAION_PQC_REQUIRED == 1), only
 *  FIPS 203/204 algorithms are accepted.  Compile with
 *  -DHIGGAION_ALLOW_CLASSICAL to permit classical algorithms in tests.
 */
void generate_keypair(HiggaionKey *key, const char *alg_name);

/**
 * Query whether an algorithm name is permitted by the current PQC policy.
 * Returns true if allowed, false if the algorithm would be rejected.
 *
 * HIG-002 mitigation: enforces algorithm allowlist at the cryptographic
 * boundary, preventing silent downgrade to classical signatures.
 */
bool higgaion_is_algorithm_allowed(const char *alg_name);

/* ── PQC signing (ML-DSA-87 via EVP_DigestSign) ──────────────────────── */

/**
 * Sign a message with domain separation using ML-DSA-87.
 * Allocates *signature; caller must free().
 */
void pqc_sign(uint8_t **signature, size_t *sig_len, const uint8_t *message,
              size_t msg_len, const char *domain, const HiggaionKey *sk);

/**
 * Verify an ML-DSA-87 signature with domain separation.
 * Returns true on valid signature.
 */
bool pqc_verify(const uint8_t *message, size_t msg_len,
                const uint8_t *signature, size_t sig_len, const char *domain,
                const HiggaionKey *pk);

/* ── Utilities ───────────────────────────────────────────────────────── */

/** Compiler-optimization-resistant memory zeroing (OPENSSL_cleanse). */
void secure_zero(void *ptr, size_t len);

/** SHA3-256 hash: out must be 32 bytes. */
void hash(uint8_t *out, const uint8_t *data, size_t len);

#endif /* PQC_CRYPTO_H */
