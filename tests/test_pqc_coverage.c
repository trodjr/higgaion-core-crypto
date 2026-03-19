#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../include/higgaion/pqc_crypto.h"

int test_edge_cases() {
    printf("Starting edge-case coverage tests...\n");

    // 1. generate_keypair NULL checks + invalid algorithms
    generate_keypair(NULL, "ML-DSA-87"); // Should return silently
    HiggaionKey key;
    higgaion_key_init(&key);
    generate_keypair(&key, "INVALID-ALG-UNKNOWN"); // Should fail and log openssl error
    assert(key.pkey == NULL);

    // 2. higgaion_key_init / free NULL checks
    higgaion_key_init(NULL);
    higgaion_key_free(NULL);
    higgaion_key_free(&key); // pkey is NULL, should return safely

    // 3. secure_zero
    uint8_t secret[16] = {0xAB, 0xCD, 0xEF};
    secure_zero(secret, sizeof(secret));
    for(int i=0; i<16; i++) assert(secret[i] == 0);

    // 4. hig_error_str
    assert(strcmp(hig_error_str(HIG_OK), "OK") == 0);
    assert(strcmp(hig_error_str(HIG_ERR_NOMEM), "out of memory") == 0);
    assert(strcmp(hig_error_str(HIG_ERR_INVALID_PARAM), "invalid parameter") == 0);
    assert(strcmp(hig_error_str(HIG_ERR_IO), "I/O error") == 0);
    assert(strcmp(hig_error_str(HIG_ERR_CRYPTO), "cryptographic error") == 0);
    assert(strcmp(hig_error_str(HIG_ERR_AUTH), "auth error") == 0);
    assert(strcmp(hig_error_str(HIG_ERR_VALIDATION), "validation error") == 0);
    assert(strcmp(hig_error_str(HIG_ERR_TIMEOUT), "timeout") == 0);
    assert(strcmp(hig_error_str(HIG_ERR_RATE_LIMITED), "rate limited") == 0);
    assert(strcmp(hig_error_str(999), "unknown error") == 0);

    // 5. hash
    uint8_t out[32];
    uint8_t data[] = "Hello World";
    assert(hash(out, data, sizeof(data) - 1) == true);
    // basic check it's populated
    bool all_zero = true;
    for(int i=0; i<32; i++) if (out[i] != 0) all_zero = false;
    assert(!all_zero);

    // 6. pqc_sign NULL & overflow checks
    uint8_t *sig = NULL;
    size_t sig_len = 0;
    pqc_sign(NULL, &sig_len, data, sizeof(data), "domain", &key); // NULL output ptr ptr? wait, first param is sig output. Null sk check:
    pqc_sign(&sig, &sig_len, data, sizeof(data), "domain", NULL); // NULL sk
    
    // Overflow check
    generate_keypair(&key, "ML-DSA-87");
    if (!key.pkey) {
        printf("[ERROR] ML-DSA-87 key generation failed.\n");
        return 1;
    }

    size_t huge_len = SIZE_MAX;
    uint8_t dummy_sig[1] = {0};
    pqc_sign(&sig, &sig_len, data, huge_len, "domain", &key); // msg_len overflow
    pqc_verify(data, huge_len, dummy_sig, sizeof(dummy_sig), "domain", &key); // msg_len overflow

    // Invalid/null verify checks
    pqc_verify(data, sizeof(data), NULL, sig_len, "domain", &key);
    pqc_verify(data, sizeof(data), sig, sig_len, "domain", NULL);
    
    // Valid sign to test verify edge cases
    pqc_sign(&sig, &sig_len, data, sizeof(data) - 1, "domain", &key);
    if(sig) {
        // test verify with corrupt data
        uint8_t bad_data[] = "Goodbye World";
        assert(!pqc_verify(bad_data, sizeof(bad_data)-1, sig, sig_len, "domain", &key));
        free(sig);
    }
    
    higgaion_key_free(&key);
    printf("Edge-case coverage tests passed!\n");
    return 0;
}

int main() {
    return test_edge_cases();
}
