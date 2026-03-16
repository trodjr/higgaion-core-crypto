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

/* ── Internal helpers ────────────────────────────────────────────────── */

static void log_openssl_error(const char *msg) {
  unsigned long err;
  bool first = true;
  while ((err = ERR_get_error())) {
    if (first) {
      log_message("ERROR", "CRYPTO", "%s: cryptographic operation failed", msg);
      first = false;
    }
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    log_message("DEBUG", "CRYPTO", "%s: detail: %s", msg, err_buf);
  }
}

/* ── Key lifecycle ───────────────────────────────────────────────────── */

void generate_keypair(HiggaionKey *key, const char *alg_name) {
  if (!key)
    return;
  key->pkey = NULL;
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

/* ── PQC signing (ML-DSA-87) ─────────────────────────────────────────── */

void pqc_sign(uint8_t **signature, size_t *sig_len, const uint8_t *message,
              size_t msg_len, const char *domain, const HiggaionKey *sk) {
  if (!sk || !sk->pkey)
    return;

  size_t dom_len = domain ? strlen(domain) : 0;
  size_t total_len = dom_len + msg_len;
  if (total_len < dom_len || total_len < msg_len) {
    log_message("ERROR", "CRYPTO", "pqc_sign: domain+message length overflow");
    return;
  }
  uint8_t *buffer = malloc(total_len);
  if (!buffer)
    return;
  if (domain)
    memcpy(buffer, domain, dom_len);
  memcpy(buffer + dom_len, message, msg_len);

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    free(buffer);
    return;
  }

  if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, sk->pkey) <= 0) {
    log_openssl_error("EVP_DigestSignInit");
    EVP_MD_CTX_free(mdctx);
    free(buffer);
    return;
  }

  if (EVP_DigestSign(mdctx, NULL, sig_len, buffer, total_len) <= 0) {
    log_openssl_error("EVP_DigestSign (size)");
    EVP_MD_CTX_free(mdctx);
    free(buffer);
    return;
  }

  *signature = malloc(*sig_len);
  if (!*signature) {
    EVP_MD_CTX_free(mdctx);
    free(buffer);
    return;
  }
  memset(*signature, 0, *sig_len);

  if (EVP_DigestSign(mdctx, *signature, sig_len, buffer, total_len) <= 0) {
    log_openssl_error("EVP_DigestSign (execute)");
    free(*signature);
    *signature = NULL;
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

  size_t dom_len = domain ? strlen(domain) : 0;
  size_t total_len = dom_len + msg_len;
  if (total_len < dom_len || total_len < msg_len) {
    log_message("ERROR", "CRYPTO",
                "pqc_verify: domain+message length overflow");
    return false;
  }
  uint8_t *buffer = malloc(total_len);
  if (!buffer)
    return false;
  if (domain)
    memcpy(buffer, domain, dom_len);
  memcpy(buffer + dom_len, message, msg_len);

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    free(buffer);
    return false;
  }

  if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pk->pkey) <= 0) {
    log_openssl_error("EVP_DigestVerifyInit");
    EVP_MD_CTX_free(mdctx);
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
  default:
    return "unknown error";
  }
}

void hash(uint8_t *out, const uint8_t *data, size_t len) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    return;
  if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) == 1 &&
      EVP_DigestUpdate(ctx, data, len) == 1) {
    unsigned int md_len = 32;
    EVP_DigestFinal_ex(ctx, out, &md_len);
  }
  EVP_MD_CTX_free(ctx);
}

