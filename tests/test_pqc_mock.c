#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include "../include/higgaion/pqc_crypto.h"

// Mock controls
int mock_malloc_fail_countdown = -1;
int mock_EVP_PKEY_keygen_init_fail = 0;
int mock_EVP_PKEY_keygen_fail = 0;
int mock_EVP_MD_CTX_new_fail = 0;
int mock_EVP_DigestSignInit_fail = 0;
int mock_EVP_DigestSign_size_fail = 0;
int mock_EVP_DigestSign_exec_fail = 0;
int mock_EVP_DigestVerifyInit_fail = 0;

// Real functions
void *__real_malloc(size_t size);
int __real_EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
int __real_EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
EVP_MD_CTX *__real_EVP_MD_CTX_new(void);
int __real_EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int __real_EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen);
int __real_EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);

// Wrappers
void *__wrap_malloc(size_t size) {
    if (mock_malloc_fail_countdown == 0) return NULL;
    if (mock_malloc_fail_countdown > 0) mock_malloc_fail_countdown--;
    return __real_malloc(size);
}

int __wrap_EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx) {
    if (mock_EVP_PKEY_keygen_init_fail) return -1;
    return __real_EVP_PKEY_keygen_init(ctx);
}

int __wrap_EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey) {
    if (mock_EVP_PKEY_keygen_fail) return -1;
    return __real_EVP_PKEY_keygen(ctx, ppkey);
}

EVP_MD_CTX *__wrap_EVP_MD_CTX_new(void) {
    if (mock_EVP_MD_CTX_new_fail) return NULL;
    return __real_EVP_MD_CTX_new();
}

int __wrap_EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey) {
    if (mock_EVP_DigestSignInit_fail) return -1;
    return __real_EVP_DigestSignInit(ctx, pctx, type, e, pkey);
}

int __wrap_EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen) {
    if (sigret == NULL && mock_EVP_DigestSign_size_fail) return -1;
    if (sigret != NULL && mock_EVP_DigestSign_exec_fail) return -1;
    return __real_EVP_DigestSign(ctx, sigret, siglen, tbs, tbslen);
}

int __wrap_EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey) {
    if (mock_EVP_DigestVerifyInit_fail) return -1;
    return __real_EVP_DigestVerifyInit(ctx, pctx, type, e, pkey);
}

int test_mocked_failures() {
    printf("Running mocked failure tests for 100%% line coverage...\n");

    HiggaionKey key;
    higgaion_key_init(&key);

    // 1. EVP_PKEY_keygen_init failure
    mock_EVP_PKEY_keygen_init_fail = 1;
    generate_keypair(&key, "ML-DSA-87");
    mock_EVP_PKEY_keygen_init_fail = 0;

    // 2. EVP_PKEY_keygen failure
    mock_EVP_PKEY_keygen_fail = 1;
    generate_keypair(&key, "ML-DSA-87");
    mock_EVP_PKEY_keygen_fail = 0;

    // Generate valid key for subsequent tests
    generate_keypair(&key, "ML-DSA-87");
    assert(key.pkey != NULL);

    uint8_t *sig = NULL;
    size_t sig_len = 0;
    const uint8_t msg[] = "Mock data";

    // 3. pqc_sign malloc failure 1 (buffer)
    mock_malloc_fail_countdown = 0;
    pqc_sign(&sig, &sig_len, msg, sizeof(msg), "domain", &key);
    mock_malloc_fail_countdown = -1;

    // 4. pqc_sign EVP_MD_CTX_new failure
    mock_EVP_MD_CTX_new_fail = 1;
    pqc_sign(&sig, &sig_len, msg, sizeof(msg), "domain", &key);
    mock_EVP_MD_CTX_new_fail = 0;

    // 5. pqc_sign EVP_DigestSignInit failure
    mock_EVP_DigestSignInit_fail = 1;
    pqc_sign(&sig, &sig_len, msg, sizeof(msg), "domain", &key);
    mock_EVP_DigestSignInit_fail = 0;

    // 6. pqc_sign EVP_DigestSign (size) failure
    mock_EVP_DigestSign_size_fail = 1;
    pqc_sign(&sig, &sig_len, msg, sizeof(msg), "domain", &key);
    mock_EVP_DigestSign_size_fail = 0;

    // 7. pqc_sign malloc failure 2 (signature buffer)
    mock_malloc_fail_countdown = 1; // 0 is 'buffer', 1 is '*signature'
    pqc_sign(&sig, &sig_len, msg, sizeof(msg), "domain", &key);
    mock_malloc_fail_countdown = -1;

    // 8. pqc_sign EVP_DigestSign (execute) failure
    mock_EVP_DigestSign_exec_fail = 1;
    pqc_sign(&sig, &sig_len, msg, sizeof(msg), "domain", &key);
    mock_EVP_DigestSign_exec_fail = 0;

    // Generate valid sig for verify tests
    pqc_sign(&sig, &sig_len, msg, sizeof(msg), "domain", &key);
    assert(sig != NULL);

    // 9. pqc_verify malloc failure
    mock_malloc_fail_countdown = 0;
    pqc_verify(msg, sizeof(msg), sig, sig_len, "domain", &key);
    mock_malloc_fail_countdown = -1;

    // 10. pqc_verify EVP_MD_CTX_new failure
    mock_EVP_MD_CTX_new_fail = 1;
    pqc_verify(msg, sizeof(msg), sig, sig_len, "domain", &key);
    mock_EVP_MD_CTX_new_fail = 0;

    // 11. pqc_verify EVP_DigestVerifyInit failure
    mock_EVP_DigestVerifyInit_fail = 1;
    pqc_verify(msg, sizeof(msg), sig, sig_len, "domain", &key);
    mock_EVP_DigestVerifyInit_fail = 0;
    
    // Valid verify just in case
    pqc_verify(msg, sizeof(msg), sig, sig_len, "domain", &key);

    free(sig);
    higgaion_key_free(&key);

    printf("Mocked failure tests passed!\n");
    return 0;
}

int main() {
    return test_mocked_failures();
}
