/**
 * @file pqc_types.h
 * @brief Minimal type definitions for the PQC Migration Engine.
 *
 * Contains only the types used unconditionally by the migration engine,
 * independent of any other dependencies.
 */
#ifndef PQC_TYPES_H
#define PQC_TYPES_H


#include <openssl/evp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Error codes ─────────────────────────────────────────────────────── */

typedef enum {
  HIG_OK = 0,
  HIG_ERR_NOMEM,
  HIG_ERR_INVALID_PARAM,
  HIG_ERR_IO,
  HIG_ERR_CRYPTO,
  HIG_ERR_AUTH,
  HIG_ERR_VALIDATION,
  HIG_ERR_TIMEOUT,
  HIG_ERR_RATE_LIMITED,
  HIG_ERR_ALGORITHM_REJECTED, /**< HIG-002: non-PQC algorithm rejected by policy */
} HigError;

#define HIG_SUCCEEDED(err) ((err) == HIG_OK)
#define HIG_FAILED(err) ((err) != HIG_OK)

const char *hig_error_str(HigError err);

/* ── PQC key parameters (FIPS 203/204) ───────────────────────────────── */

#define KEM_CIPHERTEXT_SIZE 1568
#define KEM_SHARED_SECRET_SIZE 32
#define KEM_PUBLIC_KEY_SIZE 1700
#define KEM_PRIVATE_KEY_SIZE 3168
#define DSA_SIG_SIZE 4627
#define PQC_ALGORITHM_NAME "ML-DSA-87"

/**
 * HIG-002: PQC-required policy flag.
 *
 * When defined (the default for production builds), generate_keypair()
 * rejects algorithms not in the PQC allowlist.  Define
 * HIGGAION_ALLOW_CLASSICAL at compile time to permit classical
 * algorithms (e.g. ED25519) for testing environments only.
 *
 *   gcc -DHIGGAION_ALLOW_CLASSICAL ...   # test builds
 *   gcc ...                                # production (PQC-only)
 */
#ifndef HIGGAION_ALLOW_CLASSICAL
#define HIGGAION_PQC_REQUIRED 1
#else
#define HIGGAION_PQC_REQUIRED 0
#endif
#define DSA_PUBLIC_KEY_SIZE 2700

/* ── Key wrapper ─────────────────────────────────────────────────────── */

typedef struct {
  EVP_PKEY *pkey;
} HiggaionKey;

/* Forward declarations */
struct HSMProvider;

#endif /* PQC_TYPES_H */
