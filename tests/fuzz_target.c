#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../include/higgaion/pqc_crypto.h"

/* libFuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;

    /* 1. Fuzz Algorithm Name Parsing / Key Generation */
    char alg_name[64] = {0};
    size_t copy_size = size > 63 ? 63 : size;
    memcpy(alg_name, data, copy_size);
    
    HiggaionKey key;
    higgaion_key_init(&key);
    
    /* Attempt to generate a key using fuzzed byte strings as the algorithm */
    generate_keypair(&key, alg_name);
    
    /* 2. Fuzz Domain Separation Buffer Limits */
    /* Only attempt signing if the key was actually generated successfully */
    if (key.pkey != NULL) {
        uint8_t *sig = NULL;
        size_t sig_len = 0;
        
        /* Provide arbitrary fuzzed data as the message to sign */
        pqc_sign(&sig, &sig_len, data, size, "fuzz_domain", &key);
        if (sig) free(sig);
    }

    /* 3. Cleanup and strict erasure marker check */
    higgaion_key_erase_durable(&key, "/tmp/fuzz_erasure.wal");
    
    return 0;
}
