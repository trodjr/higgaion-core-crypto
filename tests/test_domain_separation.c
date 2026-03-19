#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/higgaion/pqc_crypto.h"

static void fill(char *buf, size_t n, char c) {
  for (size_t i = 0; i < n; i++)
    buf[i] = c;
  buf[n] = '\0';
}

int main(void) {
  printf("Running domain separation adversarial tests...\n");

  HiggaionKey key;
  higgaion_key_init(&key);

#ifdef HIGGAION_ALLOW_CLASSICAL
  generate_keypair(&key, "ED25519");
#else
  generate_keypair(&key, "ML-DSA-87");
  if (!key.pkey) {
    printf("[WARN] ML-DSA-87 not supported, falling back to ED25519.\n");
    generate_keypair(&key, "ED25519");
  }
#endif
  if (!key.pkey) {
    printf("[ERROR] Failed to generate any signing key.\n");
    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Test 1: Prefix-collision resistance                                 */
  /* Old broken construction: ("A","BC") == ("AB","C")                    */
  /* ------------------------------------------------------------------ */
  {
    const uint8_t msg1[] = "BC";
    const char *dom1 = "A";

    uint8_t *sig = NULL;
    size_t sig_len = 0;
    pqc_sign(&sig, &sig_len, msg1, sizeof(msg1) - 1, dom1, &key);
    assert(sig != NULL);
    assert(sig_len > 0);

    const uint8_t msg2[] = "C";
    const char *dom2 = "AB";
    bool ok = pqc_verify(msg2, sizeof(msg2) - 1, sig, sig_len, dom2, &key);
    assert(ok == false);

    free(sig);
  }

  /* ------------------------------------------------------------------ */
  /* Test 2: Reject overlong domains (no truncation equivalence classes)  */
  /* ------------------------------------------------------------------ */
  {
    char dom_ok[HIGGAION_DOMAIN_MAX_LEN + 1];
    char dom_too_long[HIGGAION_DOMAIN_MAX_LEN + 2];

    fill(dom_ok, HIGGAION_DOMAIN_MAX_LEN, 'A');
    fill(dom_too_long, HIGGAION_DOMAIN_MAX_LEN, 'A');
    dom_too_long[HIGGAION_DOMAIN_MAX_LEN] = 'B';
    dom_too_long[HIGGAION_DOMAIN_MAX_LEN + 1] = '\0';

    const uint8_t msg[] = "payload";

    uint8_t *sig = (uint8_t *)0x1; /* sentinel; must be cleared on failure */
    size_t sig_len = 123;
    pqc_sign(&sig, &sig_len, msg, sizeof(msg) - 1, dom_too_long, &key);
    assert(sig == NULL);
    assert(sig_len == 0);

    /* Verification must also reject overlong domains */
    uint8_t *sig_ok = NULL;
    size_t sig_ok_len = 0;
    pqc_sign(&sig_ok, &sig_ok_len, msg, sizeof(msg) - 1, dom_ok, &key);
    assert(sig_ok != NULL);
    assert(sig_ok_len > 0);

    bool ok = pqc_verify(msg, sizeof(msg) - 1, sig_ok, sig_ok_len, dom_too_long,
                         &key);
    assert(ok == false);

    free(sig_ok);
  }

  higgaion_key_free(&key);

  printf("Domain separation adversarial tests passed.\n");
  return 0;
}
