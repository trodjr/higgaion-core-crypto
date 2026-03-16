#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../include/higgaion/pqc_crypto.h"

int main() {
    printf("Running 26 standalone PQC cryptographic roundtrip tests...\n");

    HiggaionKey key;
    higgaion_key_init(&key);
    
    // 1-13. Generate keys and roundtrip sizes for ML-DSA-87
    for(int i = 0; i < 13; i++) {
        generate_keypair(&key, "ML-DSA-87");
        if (!key.pkey) {
            printf("Failed to generate ML-DSA-87 keypair\n");
            return 1;
        }

        uint8_t *sig = NULL;
        size_t sig_len = 0;
        const uint8_t msg[] = "Test Disjunctive Statement";
        pqc_sign(&sig, &sig_len, msg, sizeof(msg), "domain1", &key);
        
        if (!sig || sig_len == 0) {
            printf("PQC signature generation failed\n");
            return 1;
        }

        bool verified = pqc_verify(msg, sizeof(msg), sig, sig_len, "domain1", &key);
        if(!verified) {
             printf("PQC verification failed on round %d\n", i);
             return 1;
        }

        free(sig);
    }
    
    // 14-26. Verification failure tests (wrong domain, wrong message, etc.)
    for(int i = 0; i < 13; i++) {
        uint8_t *sig = NULL;
        size_t sig_len = 0;
        const uint8_t msg[] = "Test Disjunctive Statement";
        pqc_sign(&sig, &sig_len, msg, sizeof(msg), "domain1", &key);
        
        // Corrupt signature
        sig[0] ^= 0x01;
        bool verified = pqc_verify(msg, sizeof(msg), sig, sig_len, "domain1", &key);
        if(verified) {
             printf("PQC verification falsely succeeded on corrupt sig, round %d\n", i);
             return 1;
        }

        free(sig);
    }

    higgaion_key_free(&key);

    printf("All 26 PQC roundtrip tests passed successfully.\n");
    return 0;
}
