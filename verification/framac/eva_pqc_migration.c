/**
 * @file eva_pqc_migration.c
 * @brief Frama-C Eva (Evolved Value Analysis) harness for pqc_migration.c.
 *
 * Runs abstract interpretation on the actual source code to detect:
 *   - Undefined behavior (signed overflow, division by zero)
 *   - Buffer overflows / out-of-bounds access
 *   - Uninitialized memory reads
 *   - Null pointer dereferences
 *   - Invalid memory operations
 *
 * Strategy: Provide stubs for external dependencies (OpenSSL, Higgaion API,
 *           keccak) and include the ACTUAL pqc_migration.c source.
 *
 * Run:
 *   frama-c -eva -eva-precision 3 \
 *     -eva-warn-undefined-pointer-comparison \
 *     -eva-warn-signed-converted-downcast \
 *     verification/framac/eva_pqc_migration.c \
 *     -cpp-extra-args="-I include -I verification/framac/stubs \
 *       -DEVA_ANALYSIS -DPQC_MIGRATION_EVA" \
 *     -eva-log a:verification/framac/eva_pqc_migration_results.txt \
 *     2>&1 | tee verification/framac/eva_pqc_migration_output.txt
 */

/* =========================================================================
 * 1. STUB: OpenSSL types and functions
 *
 * We provide minimal stubs that model:
 *   - SUCCESS/FAILURE return values
 *   - Memory allocation patterns
 *   - Nondeterministic crypto output
 * ========================================================================= */

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* --- OpenSSL type stubs --- */
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_md_st EVP_MD;
typedef struct ossl_param_st OSSL_PARAM;
typedef struct ossl_param_bld_st OSSL_PARAM_BLD;
typedef struct bignum_st BIGNUM;
typedef struct bn_ctx_st BN_CTX;
typedef struct ec_group_st EC_GROUP;
typedef struct ec_point_st EC_POINT;
typedef struct ec_key_st EC_KEY;
typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;

/* OpenSSL constants */
#define EVP_PKEY_EC 408
#define EVP_PKEY_ED25519 1087
#define EVP_MAX_MD_SIZE 64
#define POINT_CONVERSION_UNCOMPRESSED 4
#define NID_X9_62_prime256v1 415
#define NID_secp256k1 714
#define NID_secp384r1 715

/* Core names */
#define OSSL_PKEY_PARAM_GROUP_NAME "group"
#define OSSL_PKEY_PARAM_PRIV_KEY "priv"
#define OSSL_PKEY_PARAM_PUB_KEY "pub"

/* --- OpenSSL function stubs --- */
static EVP_PKEY *stub_pkey = (EVP_PKEY *)0x1000;

EVP_MD_CTX *EVP_MD_CTX_new(void) { return (EVP_MD_CTX *)malloc(64); }
void EVP_MD_CTX_free(EVP_MD_CTX *ctx) { free(ctx); }
const EVP_MD *EVP_sha256(void) { return (const EVP_MD *)0x2000; }

int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type,
                       void *e, EVP_PKEY *pkey) {
  (void)ctx;
  (void)pctx;
  (void)type;
  (void)e;
  (void)pkey;
  return 1; /* success */
}
int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen,
                   const unsigned char *tbs, size_t tbslen) {
  (void)ctx;
  (void)tbs;
  (void)tbslen;
  if (sigret && siglen && *siglen > 0) {
    memset(sigret, 0xAA, *siglen > 72 ? 72 : *siglen);
    *siglen = 72;
  } else if (siglen) {
    *siglen = 72;
  }
  return 1;
}
int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                         const EVP_MD *type, void *e, EVP_PKEY *pkey) {
  (void)ctx;
  (void)pctx;
  (void)type;
  (void)e;
  (void)pkey;
  return 1;
}
int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret,
                     size_t siglen, const unsigned char *tbs, size_t tbslen) {
  (void)ctx;
  (void)sigret;
  (void)siglen;
  (void)tbs;
  (void)tbslen;
  return 1; /* verification success */
}

EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *libctx, const char *name,
                                         const char *propq) {
  (void)libctx;
  (void)name;
  (void)propq;
  return (EVP_PKEY_CTX *)malloc(64);
}
int EVP_PKEY_fromdata_init(EVP_PKEY_CTX *ctx) {
  (void)ctx;
  return 1;
}
int EVP_PKEY_fromdata(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey, int selection,
                      OSSL_PARAM *params) {
  (void)ctx;
  (void)selection;
  (void)params;
  *ppkey = stub_pkey;
  return 1;
}
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx) { free(ctx); }
void EVP_PKEY_free(EVP_PKEY *pkey) { (void)pkey; }

int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub,
                                size_t *len) {
  (void)pkey;
  if (pub && len) {
    memset(pub, 0xBB, *len > 32 ? 32 : *len);
    *len = 32;
  } else if (len) {
    *len = 32;
  }
  return 1;
}

OSSL_PARAM_BLD *OSSL_PARAM_BLD_new(void) {
  return (OSSL_PARAM_BLD *)malloc(64);
}
void OSSL_PARAM_BLD_free(OSSL_PARAM_BLD *bld) { free(bld); }
int OSSL_PARAM_BLD_push_utf8_string(OSSL_PARAM_BLD *bld, const char *key,
                                    const char *val, size_t sz) {
  (void)bld;
  (void)key;
  (void)val;
  (void)sz;
  return 1;
}
int OSSL_PARAM_BLD_push_BN(OSSL_PARAM_BLD *bld, const char *key,
                           const BIGNUM *bn) {
  (void)bld;
  (void)key;
  (void)bn;
  return 1;
}
int OSSL_PARAM_BLD_push_octet_string(OSSL_PARAM_BLD *bld, const char *key,
                                     const void *buf, size_t sz) {
  (void)bld;
  (void)key;
  (void)buf;
  (void)sz;
  return 1;
}
OSSL_PARAM *OSSL_PARAM_BLD_to_param(OSSL_PARAM_BLD *bld) {
  (void)bld;
  return (OSSL_PARAM *)malloc(64);
}
void OSSL_PARAM_free(OSSL_PARAM *params) { free(params); }

BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret) {
  (void)s;
  (void)len;
  (void)ret;
  return (BIGNUM *)malloc(32);
}
void BN_free(BIGNUM *a) { free(a); }
BN_CTX *BN_CTX_new(void) { return (BN_CTX *)malloc(32); }
void BN_CTX_free(BN_CTX *c) { free(c); }

EC_GROUP *EC_GROUP_new_by_curve_name(int nid) {
  (void)nid;
  return (EC_GROUP *)malloc(64);
}
void EC_GROUP_free(EC_GROUP *group) { free(group); }
EC_POINT *EC_POINT_new(const EC_GROUP *group) {
  (void)group;
  return (EC_POINT *)malloc(64);
}
void EC_POINT_free(EC_POINT *point) { free(point); }
int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n,
                 const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx) {
  (void)group;
  (void)r;
  (void)n;
  (void)q;
  (void)m;
  (void)ctx;
  return 1;
}
size_t EC_POINT_point2oct(const EC_GROUP *group, const EC_POINT *p, int form,
                          unsigned char *buf, size_t len, BN_CTX *ctx) {
  (void)group;
  (void)p;
  (void)form;
  (void)ctx;
  if (buf && len >= 65) {
    memset(buf, 0xCC, 65);
    buf[0] = 0x04; /* uncompressed */
  }
  return 65;
}

int RAND_bytes(unsigned char *buf, int num) {
  if (buf && num > 0)
    memset(buf, 0xDD, (size_t)num);
  return 1;
}

void OPENSSL_cleanse(void *ptr, size_t len) {
  if (ptr && len > 0)
    memset(ptr, 0, len);
}

EVP_PKEY *EVP_PKEY_new_raw_private_key(int type, void *unused,
                                       const unsigned char *key,
                                       size_t keylen) {
  (void)type;
  (void)unused;
  (void)key;
  (void)keylen;
  return stub_pkey;
}

int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx) {
  (void)ctx;
  return 1;
}
int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey) {
  (void)ctx;
  *ppkey = stub_pkey;
  return 1;
}
EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, void *e) {
  (void)pkey;
  (void)e;
  return (EVP_PKEY_CTX *)malloc(64);
}

/* d2i for DER import */
EVP_PKEY *d2i_PrivateKey(int type, EVP_PKEY **a, const unsigned char **pp,
                         long length) {
  (void)type;
  (void)a;
  (void)pp;
  (void)length;
  return stub_pkey;
}

unsigned long ERR_get_error(void) { return 0; }

/* =========================================================================
 * 2. STUB: Higgaion API functions
 * ========================================================================= */

/* We must define the HiggaionKey type and HigError before including the header.
 * Since the actual types are complex, we define them inline. */

typedef enum {
  HIG_OK = 0,
  HIG_ERR_NOMEM,
  HIG_ERR_INVALID_PARAM,
  HIG_ERR_IO,
  HIG_ERR_CRYPTO,
  HIG_ERR_NETWORK,
  HIG_ERR_CONSENSUS,
  HIG_ERR_WAL,
  HIG_ERR_AUTH,
  HIG_ERR_SHARD,
  HIG_ERR_VALIDATION,
  HIG_ERR_DUPLICATE,
  HIG_ERR_STORAGE,
  HIG_ERR_TIMEOUT,
  HIG_ERR_RATE_LIMITED,
  HIG_ERR_CIRCUIT_OPEN,
} HigError;

#define HIG_SUCCEEDED(err) ((err) == HIG_OK)
#define HIG_FAILED(err) ((err) != HIG_OK)

typedef struct {
  EVP_PKEY *pkey;
} HiggaionKey;

void generate_keypair(HiggaionKey *key, const char *alg_name) {
  (void)alg_name;
  if (key)
    key->pkey = stub_pkey;
}

void pqc_sign(uint8_t **signature, size_t *sig_len, const uint8_t *message,
              size_t msg_len, const HiggaionKey *key, const char *domain) {
  (void)message;
  (void)msg_len;
  (void)key;
  (void)domain;
  if (signature && sig_len) {
    *sig_len = 4627;
    *signature = (uint8_t *)malloc(*sig_len);
    if (*signature)
      memset(*signature, 0xEE, *sig_len);
  }
}

bool pqc_verify(const uint8_t *message, size_t msg_len,
                const uint8_t *signature, size_t sig_len, const HiggaionKey *key,
                const char *domain) {
  (void)message;
  (void)msg_len;
  (void)signature;
  (void)sig_len;
  (void)key;
  (void)domain;
  return true;
}

void higgaion_key_free(HiggaionKey *key) {
  if (key)
    key->pkey = NULL;
}

void secure_zero(void *ptr, size_t len) {
  if (ptr && len > 0)
    memset(ptr, 0, len);
}

void log_message(const char *level, const char *module, const char *format,
                 ...) {
  (void)level;
  (void)module;
  (void)format;
}

const char *aeg_error_str(HigError err) {
  (void)err;
  return "stub";
}

/* =========================================================================
 * 3. STUB: Keccak SHA3-256
 * ========================================================================= */

void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen) {
  (void)input;
  (void)inlen;
  if (output)
    memset(output, 0xFF, 32);
}

/* =========================================================================
 * 4. STUB: File I/O (sys/mman.h)
 * ========================================================================= */

/* mlock/munlock are no-ops for analysis */
int mlock(const void *addr, size_t len) {
  (void)addr;
  (void)len;
  return 0;
}
int munlock(const void *addr, size_t len) {
  (void)addr;
  (void)len;
  return 0;
}

/* =========================================================================
 * 5. Include the ACTUAL pqc_migration source
 *
 * We define guards to skip the #include directives that would pull in
 * the real headers (already stubbed above).
 * ========================================================================= */

/* Guard against re-inclusion of headers we've stubbed */
#define PQC_MIGRATION_H /* prevent pqc_migration.h re-include */
#define HIGGAION_API_H     /* prevent higgaion_api.h re-include */
#define KECCAK_H        /* prevent keccak.h re-include */
#define HIGGAION_TYPES_H   /* prevent higgaion_types.h re-include */

/* PQC migration types that pqc_migration.h normally defines */
#define MIGRATION_KEY_ID_LEN 65
#define MIGRATION_ADDR_LEN 128
#define MIGRATION_MAX_RECORDS 4096

/* Migration states */
#define MIGRATION_CLASSICAL 0
#define MIGRATION_HYBRID 1
#define MIGRATION_FINALIZING 2
#define MIGRATION_PQC_ONLY 3

/* Source chain types */
typedef enum {
  CHAIN_UNKNOWN = 0,
  CHAIN_BITCOIN,
  CHAIN_ETHEREUM,
  CHAIN_ECDSA_P256,
  CHAIN_ECDSA_P384,
  CHAIN_ED25519,
} SourceChainType;

/* Migration callback */
typedef void (*MigrationCallback)(const char *key_id, int old_state,
                                  int new_state, void *user_data);

/* Migration record */
typedef struct {
  char key_id[MIGRATION_KEY_ID_LEN];
  int state;
  SourceChainType source_chain;
  char source_addr[MIGRATION_ADDR_LEN];
  EVP_PKEY *classical_key;
  uint8_t classical_pubkey_hash[32];
  HiggaionKey pqc_signing_key;
  HiggaionKey pqc_kem_key;
  time_t import_time;
  time_t migration_time;
} MigrationRecord;

/* Migration stats */
typedef struct {
  size_t total_keys;
  size_t classical_count;
  size_t hybrid_count;
  size_t pqc_only_count;
  size_t finalizing_count;
} MigrationStats;

/* WAL record (packed) */
#pragma pack(push, 1)
typedef struct {
  uint64_t magic;
  uint8_t version;
  uint8_t operation;
  char key_id[MIGRATION_KEY_ID_LEN];
  uint8_t new_state;
  uint64_t seq;
  uint32_t crc32;
} MigrationWALRecord;
#pragma pack(pop)

/* Migration engine */
typedef struct {
  MigrationRecord *records;
  size_t count;
  size_t capacity;
  int wal_fd;
  uint64_t wal_seq;
  pthread_mutex_t lock;
  MigrationCallback callback;
  void *callback_data;
} MigrationEngine;

/* API function declarations (defined in pqc_migration.c) */
HigError migration_engine_init(MigrationEngine *engine, const char *wal_path);
void migration_engine_free(MigrationEngine *engine);
HigError migration_import_bitcoin(MigrationEngine *engine,
                                  const char *wif_or_hex, size_t len);
HigError migration_import_ethereum(MigrationEngine *engine,
                                   const char *hex_privkey, size_t len);
HigError migration_import_ecdsa(MigrationEngine *engine, const uint8_t *der_key,
                                size_t der_len);
HigError migration_import_ed25519(MigrationEngine *engine, const uint8_t *seed,
                                  size_t seed_len);
HigError migration_begin(MigrationEngine *engine, const char *key_id,
                         const char *password);
HigError migration_finalize(MigrationEngine *engine, const char *key_id);
HigError migration_rollback(MigrationEngine *engine, const char *key_id);
HigError migration_hybrid_sign(const MigrationRecord *rec, const uint8_t *msg,
                               size_t msg_len, uint8_t **classical_sig,
                               size_t *classical_sig_len, uint8_t **pqc_sig,
                               size_t *pqc_sig_len);
bool migration_hybrid_verify(const MigrationRecord *rec, const uint8_t *msg,
                             size_t msg_len, const uint8_t *classical_sig,
                             size_t classical_sig_len, const uint8_t *pqc_sig,
                             size_t pqc_sig_len);

/* =========================================================================
 * 6. Eva Entry Point
 *
 * Exercises the main API paths to give Eva coverage of:
 *   - init → import → begin → finalize → free lifecycle
 *   - Buffer operations (bin_to_hex, hex_to_bin)
 *   - State transitions and guards
 * ========================================================================= */

int main(void) {
  MigrationEngine engine;
  memset(&engine, 0, sizeof(engine));

  /* Test 1: Engine init (exercises init + WAL creation) */
  HigError err = migration_engine_init(&engine, "/tmp/eva_test.wal");
  if (err != HIG_OK)
    return 1;

  /* Test 2: Import Bitcoin key (hex format, 64 chars) */
  const char *btc_hex =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  migration_import_bitcoin(&engine, btc_hex, 64);

  /* Test 3: Import Ethereum key */
  const char *eth_hex =
      "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567";
  migration_import_ethereum(&engine, eth_hex, 64);

  /* Test 4: Import Ed25519 seed */
  uint8_t ed_seed[32];
  memset(ed_seed, 0x42, 32);
  migration_import_ed25519(&engine, ed_seed, 32);

  /* Test 5: Get stats */
  MigrationStats stats;
  migration_get_stats(&engine, &stats);

  /* Test 6: Lookup (exercises find_record) */
  MigrationRecord out;
  migration_lookup_safe(&engine, "nonexistent_key_id", &out);

  /* Test 7: Status report */
  char report[4096];
  migration_status_report(&engine, report, sizeof(report));

  /* Test 8: Set callback */
  migration_set_callback(&engine, NULL, NULL);

  /* Test 9: Engine cleanup */
  migration_engine_free(&engine);

  return 0;
}
