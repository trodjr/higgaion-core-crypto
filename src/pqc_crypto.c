/**
 * @file pqc_crypto.c
 * @brief PQC cryptographic primitives for the migration engine.
 *
 * Provides ML-DSA OpenSSL wrappers and utility functions for
 * the isolated PQC verification module.
 */
#define _POSIX_C_SOURCE 200809L
#include "../include/higgaion/pqc_crypto.h"
#include "../include/higgaion/pqc_log.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/* ── Internal helpers ────────────────────────────────────────────────── */

/* Domain separation encoding
 *
 * IMPORTANT: The mapping (domain, message) -> signed bytes must be injective.
 * Do NOT concatenate raw strings without lengths: it enables cross-domain
 * confusion (e.g., ("A","BC") == ("AB","C")).
 */
static const uint8_t HIGGAION_DS_PREFIX[] = "HIGGAION_DS_V1";

static void write_u32_be(uint8_t out[4], uint32_t v) {
  out[0] = (uint8_t)((v >> 24) & 0xFFu);
  out[1] = (uint8_t)((v >> 16) & 0xFFu);
  out[2] = (uint8_t)((v >> 8) & 0xFFu);
  out[3] = (uint8_t)(v & 0xFFu);
}

static void write_u64_be(uint8_t out[8], uint64_t v) {
  out[0] = (uint8_t)((v >> 56) & 0xFFu);
  out[1] = (uint8_t)((v >> 48) & 0xFFu);
  out[2] = (uint8_t)((v >> 40) & 0xFFu);
  out[3] = (uint8_t)((v >> 32) & 0xFFu);
  out[4] = (uint8_t)((v >> 24) & 0xFFu);
  out[5] = (uint8_t)((v >> 16) & 0xFFu);
  out[6] = (uint8_t)((v >> 8) & 0xFFu);
  out[7] = (uint8_t)(v & 0xFFu);
}

static bool build_domain_separated_message(uint8_t **out, size_t *out_len,
                                           const uint8_t *message,
                                           size_t msg_len,
                                           const char *domain) {
  if (!out || !out_len)
    return false;

  *out = NULL;
  *out_len = 0;

  if (msg_len > 0 && !message) {
    log_message("ERROR", "CRYPTO",
                "domain separation: msg_len > 0 but message is NULL");
    return false;
  }

  if (msg_len > 104857600) { /* HIG-010 FIX: 100 MB max message size to prevent OOM DOS */
    log_message("ERROR", "CRYPTO",
                "domain separation: msg_len %zu exceeds 100MB bounds", msg_len);
    return false;
  }

  size_t dom_len = 0;
  if (domain) {
    dom_len = strnlen(domain, (size_t)HIGGAION_DOMAIN_MAX_LEN + 1);
    if (dom_len > (size_t)HIGGAION_DOMAIN_MAX_LEN) {
      log_message("ERROR", "CRYPTO",
                  "domain separation: domain tag too long (max=%d)",
                  HIGGAION_DOMAIN_MAX_LEN);
      return false;
    }
  }

  const size_t prefix_len = sizeof(HIGGAION_DS_PREFIX) - 1;

  size_t total_len = prefix_len;
  if (SIZE_MAX - total_len < 4)
    return false;
  total_len += 4;
  if (SIZE_MAX - total_len < dom_len)
    return false;
  total_len += dom_len;
  if (SIZE_MAX - total_len < 8)
    return false;
  total_len += 8;
  if (SIZE_MAX - total_len < msg_len)
    return false;
  total_len += msg_len;

  uint8_t *buf = malloc(total_len);
  if (!buf)
    return false;

  uint8_t *p = buf;
  memcpy(p, HIGGAION_DS_PREFIX, prefix_len);
  p += prefix_len;

  write_u32_be(p, (uint32_t)dom_len);
  p += 4;

  if (dom_len > 0) {
    memcpy(p, domain, dom_len);
    p += dom_len;
  }

  write_u64_be(p, (uint64_t)msg_len);
  p += 8;

  if (msg_len > 0) {
    memcpy(p, message, msg_len);
  }

  *out = buf;
  *out_len = total_len;
  return true;
}

static void log_openssl_error(const char *msg) {
  unsigned long err;
  bool first = true;
  while ((err = ERR_get_error())) {
    if (first) {
      log_message("ERROR", "CRYPTO", "%s: cryptographic operation failed", msg);
      first = false;
    }
    /* flawfinder: ignore */
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    log_message("DEBUG", "CRYPTO", "%s: detail: %s", msg, err_buf);
  }
}

/* ── Algorithm allowlist (HIG-002) ───────────────────────────────────── */

/**
 * PQC-approved algorithm names.  These are the only algorithms
 * permitted in production builds when HIGGAION_PQC_REQUIRED == 1.
 */
static const char *const HIGGAION_PQC_ALLOWLIST[]
    __attribute__((unused)) = {
    "ML-DSA-87",   /* FIPS 204 signature */
    "ML-DSA-65",   /* FIPS 204 signature (level 3) */
    "ML-DSA-44",   /* FIPS 204 signature (level 2) */
    "ML-KEM-1024", /* FIPS 203 KEM */
    "ML-KEM-768",  /* FIPS 203 KEM (level 3) */
    "ML-KEM-512",  /* FIPS 203 KEM (level 2) */
    NULL};

bool higgaion_is_algorithm_allowed(const char *alg_name) {
  if (!alg_name)
    return false;

#if HIGGAION_PQC_REQUIRED
  /* Production: only PQC algorithms permitted */
  for (const char *const *p = HIGGAION_PQC_ALLOWLIST; *p; ++p) {
    if (strcmp(alg_name, *p) == 0)
      return true;
  }
  return false;
#else
  /* Test builds: all OpenSSL-supported algorithms permitted */
  (void)alg_name;
  return true;
#endif
}

/* ── Key lifecycle ───────────────────────────────────────────────────── */

void generate_keypair(HiggaionKey *key, const char *alg_name) {
  if (!key)
    return;

  /* HIG-002 FIX: Enforce algorithm policy at the cryptographic boundary.
   * Production builds reject non-PQC algorithms to prevent silent
   * downgrade to classical signatures (e.g. ED25519).  Test builds
   * compiled with -DHIGGAION_ALLOW_CLASSICAL bypass this check. */
  if (!higgaion_is_algorithm_allowed(alg_name)) {
    log_message("ERROR", "CRYPTO",
                "generate_keypair: algorithm '%s' rejected by PQC policy "
                "(only FIPS 203/204 algorithms permitted in production)",
                alg_name ? alg_name : "(null)");
    key->pkey = NULL;
    return;
  }

  /* HIG-004 FIX: Free any existing key to prevent memory leak on
   * regeneration.  The old code blindly set pkey = NULL, leaking the
   * previous EVP_PKEY allocation if the caller reused the struct. */
  if (key->pkey != NULL) {
    EVP_PKEY_free(key->pkey);
    key->pkey = NULL;
  }
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
  if (!ctx) {
    log_openssl_error("EVP_PKEY_CTX_new_from_name");
    return;
  }

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    log_openssl_error("EVP_PKEY_keygen_init");
    EVP_PKEY_CTX_free(ctx);
    return;
  }

  if (EVP_PKEY_keygen(ctx, &key->pkey) <= 0) {
    log_openssl_error("EVP_PKEY_keygen");
    EVP_PKEY_CTX_free(ctx);
    return;
  }

  EVP_PKEY_CTX_free(ctx);

  if (key->pkey) {
    const OSSL_PROVIDER *prov = EVP_PKEY_get0_provider(key->pkey);
    if (prov) {
      log_message("INFO", "CRYPTO", "Generated %s keypair via provider: %s",
                  alg_name, OSSL_PROVIDER_get0_name(prov));
    }
  }
}

void higgaion_key_init(HiggaionKey *key) {
  if (key)
    key->pkey = NULL;
}

void higgaion_key_free(HiggaionKey *key) {
  if (key && key->pkey) {
    EVP_PKEY_free(key->pkey);
    key->pkey = NULL;
  }
}

/* HIG-007 & HIG-009 FIX: Durable WAL marker for erasure to ensure crash recovery safety */
bool higgaion_key_erase_durable(HiggaionKey *key, const char *wal_path) {
  if (!key || !key->pkey || !wal_path) return false;
  
  /* HIG-009 FIX: Atomic rename, O_TRUNC, and directory fsync for crash consistency */
  char tmp_path[1024];
  int rc = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", wal_path);
  if (rc < 0 || (size_t)rc >= sizeof(tmp_path)) return false;

  int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0600);
  if (fd < 0) return false;
  
  /* Write ERASING marker BEFORE destroying key in memory */
  if (write(fd, "ERASING", 7) != 7) { close(fd); return false; }
  fsync(fd);
  
  /* Destroy key material */
  EVP_PKEY_free(key->pkey);
  key->pkey = NULL;
  
  /* Write ERASED monotonic marker AFTER destruction is complete */
  lseek(fd, 0, SEEK_SET);
  if (write(fd, "ERASED ", 7) != 7) { close(fd); return false; }
  fsync(fd);
  close(fd);
  
  if (rename(tmp_path, wal_path) != 0) return false;
  
  /* Fsync parent directory */
  const char *last_slash = strrchr(wal_path, '/');
  if (last_slash) {
    size_t dir_len = (size_t)(last_slash - wal_path);
    if (dir_len > 0 && dir_len < sizeof(tmp_path)) {
      char dir_path[1024];
      strncpy(dir_path, wal_path, dir_len);
      dir_path[dir_len] = '\0';
      int dir_fd = open(dir_path, O_RDONLY);
      if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
      }
    }
  }
  return true;
}

int higgaion_key_up_ref(HiggaionKey *dst, const HiggaionKey *src) {
  if (!dst || !src || !src->pkey)
    return 0;

  /* HIG-003 FIX: Safely share an EVP_PKEY between independent owners
   * (e.g., PrivateKey and PublicKey FFI structs) by incrementing the
   * OpenSSL reference count instead of raw pointer aliasing.  Each
   * owner can now call EVP_PKEY_free / higgaion_key_free independently
   * without triggering use-after-free or double-free. */
  if (EVP_PKEY_up_ref((EVP_PKEY *)src->pkey) != 1) {
    log_openssl_error("EVP_PKEY_up_ref");
    return 0;
  }
  dst->pkey = src->pkey;
  return 1;
}

/* ── PQC signing (ML-DSA-87) ─────────────────────────────────────────── */

void pqc_sign(uint8_t **signature, size_t *sig_len, const uint8_t *message,
              size_t msg_len, const char *domain, const HiggaionKey *sk) {
  if (signature)
    *signature = NULL;
  if (sig_len)
    *sig_len = 0;

  if (!signature || !sig_len) {
    log_message("ERROR", "CRYPTO", "pqc_sign: invalid output pointers");
    return;
  }
  if (!sk || !sk->pkey)
    return;

  uint8_t *buffer = NULL;
  size_t total_len = 0;
  if (!build_domain_separated_message(&buffer, &total_len, message, msg_len,
                                      domain)) {
    return;
  }

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    OPENSSL_cleanse(buffer, total_len);
    free(buffer);
    return;
  }

  if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, sk->pkey) <= 0) {
    log_openssl_error("EVP_DigestSignInit");
    EVP_MD_CTX_free(mdctx);
    OPENSSL_cleanse(buffer, total_len);
    free(buffer);
    return;
  }

  if (EVP_DigestSign(mdctx, NULL, sig_len, buffer, total_len) <= 0) {
    log_openssl_error("EVP_DigestSign (size)");
    EVP_MD_CTX_free(mdctx);
    OPENSSL_cleanse(buffer, total_len);
    free(buffer);
    return;
  }

  *signature = malloc(*sig_len);
  if (!*signature) {
    EVP_MD_CTX_free(mdctx);
    OPENSSL_cleanse(buffer, total_len);
    free(buffer);
    return;
  }
  memset(*signature, 0, *sig_len);

  if (EVP_DigestSign(mdctx, *signature, sig_len, buffer, total_len) <= 0) {
    log_openssl_error("EVP_DigestSign (execute)");
    free(*signature);
    *signature = NULL;
    *sig_len = 0;
  }

  EVP_MD_CTX_free(mdctx);
  OPENSSL_cleanse(buffer, total_len);
  free(buffer);
}

bool pqc_verify(const uint8_t *message, size_t msg_len,
                const uint8_t *signature, size_t sig_len, const char *domain,
                const HiggaionKey *pk) {
  if (!pk || !pk->pkey || !signature)
    return false;
  if (sig_len == 0)
    return false;
  if (msg_len > 0 && !message) {
    log_message("ERROR", "CRYPTO",
                "pqc_verify: msg_len > 0 but message is NULL");
    return false;
  }

  uint8_t *buffer = NULL;
  size_t total_len = 0;
  if (!build_domain_separated_message(&buffer, &total_len, message, msg_len,
                                      domain)) {
    return false;
  }

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    OPENSSL_cleanse(buffer, total_len);
    free(buffer);
    return false;
  }

  if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pk->pkey) <= 0) {
    log_openssl_error("EVP_DigestVerifyInit");
    EVP_MD_CTX_free(mdctx);
    OPENSSL_cleanse(buffer, total_len);
    free(buffer);
    return false;
  }

  int rc = EVP_DigestVerify(mdctx, signature, sig_len, buffer, total_len);

  if (rc != 1) {
    log_message("ERROR", "CRYPTO",
                "EVP_DigestVerify failed (rc=%d, msg_len=%zu, sig_len=%zu)", rc,
                msg_len, sig_len);
    log_openssl_error("EVP_DigestVerify");
  }
  EVP_MD_CTX_free(mdctx);
  OPENSSL_cleanse(buffer, total_len);
  free(buffer);

  return (rc == 1);
}

/* ── Utilities ───────────────────────────────────────────────────────── */

void secure_zero(void *ptr, size_t len) { OPENSSL_cleanse(ptr, len); }

const char *hig_error_str(HigError err) {
  switch (err) {
  case HIG_OK:
    return "OK";
  case HIG_ERR_NOMEM:
    return "out of memory";
  case HIG_ERR_INVALID_PARAM:
    return "invalid parameter";
  case HIG_ERR_IO:
    return "I/O error";
  case HIG_ERR_CRYPTO:
    return "cryptographic error";
  case HIG_ERR_AUTH:
    return "auth error";
  case HIG_ERR_VALIDATION:
    return "validation error";
  case HIG_ERR_TIMEOUT:
    return "timeout";
  case HIG_ERR_RATE_LIMITED:
    return "rate limited";
  case HIG_ERR_ALGORITHM_REJECTED:
    return "algorithm rejected by PQC policy";
  default:
    return "unknown error";
  }
}

bool hash(uint8_t *out, const uint8_t *data, size_t len) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    secure_zero(out, 32);
    return false;
  }
  bool success = false;
  if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) == 1 &&
      EVP_DigestUpdate(ctx, data, len) == 1) {
    unsigned int md_len = 32;
    if (EVP_DigestFinal_ex(ctx, out, &md_len) == 1) {
      success = true;
    }
  }
  EVP_MD_CTX_free(ctx);
  if (!success) {
    secure_zero(out, 32);
  }
  return success;
}
