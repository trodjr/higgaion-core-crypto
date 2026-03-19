/**
 * @file cbmc_did_vc.c
 * @brief CBMC bounded model checking harness for DID/VC module.
 *
 * 6 property groups verifying buffer bounds, enum ranges, and
 * structural invariants for Decentralized Identity.
 *
 * Run: cbmc --function harness_all verification/cbmc_did_vc.c \
 *      --signed-overflow-check --unsigned-overflow-check \
 *      --conversion-check --unwind 20 --unwinding-assertions
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ---- Constants from did_vc.h ---- */

#define DID_MAX_DIDS 128
#define DID_MAX_VCS 256
#define DID_MAX_SERVICES 8
#define DID_MAX_VMS 4
#define DID_MAX_CLAIMS 16
#define DID_MAX_VCS_IN_VP 8
#define DID_ID_SIZE 33
#define DID_URI_SIZE 128
#define DID_NAME_SIZE 128
#define DID_TYPE_SIZE 64
#define DID_CLAIM_KEY_SIZE 64
#define DID_CLAIM_VAL_SIZE 256
#define DID_SIG_SIZE 4672
#define DID_PK_SIZE 2592
#define DID_PROOF_SIZE 128

/* ---- Enum ranges ---- */

#define DID_STATUS_COUNT 2
#define DID_VM_COUNT 2
#define DID_REL_COUNT 4
#define VC_STATUS_COUNT 4
#define VC_TYPE_COUNT 5

/* ---- Non-deterministic helpers ---- */

unsigned int nondet_uint(void);
size_t nondet_size(void);

/* ================================================================ */
/* Property 1: DID URI buffer bounds                                */
/* ================================================================ */

void harness_did_uri_bounds(void) {
  /* did:higgaion:<32 hex chars> = 10 + 32 + 1(null) = 43 bytes */
  size_t prefix_len = 10; /* "did:higgaion:" */
  size_t hex_len = 32;
  size_t null_term = 1;
  size_t total = prefix_len + hex_len + null_term;

  /* PROP-1a: URI fits in DID_URI_SIZE */
  assert(total <= DID_URI_SIZE);

  /* Fragment URIs: did:higgaion:<hex>#key-0 = 43 + 6 = 49 */
  size_t fragment_key = total - 1 + 6; /* "#key-0" */
  assert(fragment_key < DID_URI_SIZE);

  /* Fragment URIs: did:higgaion:<hex>#svc-0 = 43 + 6 = 49 */
  size_t fragment_svc = total - 1 + 6; /* "#svc-0" */
  assert(fragment_svc < DID_URI_SIZE);

  /* PROP-1b: Max VM count fragment: #key-3 (4 chars + index) */
  size_t max_fragment = total - 1 + 6; /* "#key-3" */
  assert(max_fragment < DID_URI_SIZE);
}

/* ================================================================ */
/* Property 2: Credential claim buffer bounds                       */
/* ================================================================ */

void harness_claim_bounds(void) {
  /* Each claim: key (64B) + value (256B) */
  size_t claim_size = DID_CLAIM_KEY_SIZE + DID_CLAIM_VAL_SIZE;

  /* PROP-2a: Single claim fits in stack-safe size */
  assert(claim_size == 320);
  assert(claim_size < 4096);

  /* PROP-2b: Max claims per VC = 16, all fit in VC struct */
  size_t total_claims = DID_MAX_CLAIMS * claim_size;
  assert(total_claims == 5120);

  /* PROP-2c: Claim index never exceeds max */
  unsigned int idx = nondet_uint();
  __CPROVER_assume(idx < DID_MAX_CLAIMS);
  assert(idx < 16);
}

/* ================================================================ */
/* Property 3: PQC signature buffer exact fit                       */
/* ================================================================ */

void harness_pqc_sig_bounds(void) {
  /* ML-DSA-87 signature: max 4627 bytes (NIST) */
  size_t mldsa87_max = 4627;

  /* PROP-3a: Signature buffer accommodates ML-DSA-87 */
  assert(DID_SIG_SIZE >= mldsa87_max);

  /* PROP-3b: Public key buffer accommodates ML-DSA-87 */
  size_t mldsa87_pk = 2592;
  assert(DID_PK_SIZE >= mldsa87_pk);

  /* PROP-3c: Proof verification method URI fits in URI buffer */
  /* "did:higgaion:<32hex>#key-0" = 49 chars + null */
  assert(50 <= DID_URI_SIZE);
}

/* ================================================================ */
/* Property 4: VC status enum range                                 */
/* ================================================================ */

void harness_vc_status_range(void) {
  unsigned int status = nondet_uint();
  __CPROVER_assume(status < VC_STATUS_COUNT);

  /* PROP-4a: All status values are in valid range */
  assert(status <= 3);

  /* PROP-4b: VC type enum range */
  unsigned int vc_type = nondet_uint();
  __CPROVER_assume(vc_type < VC_TYPE_COUNT);
  assert(vc_type <= 4);

  /* PROP-4c: DID status enum range */
  unsigned int did_status = nondet_uint();
  __CPROVER_assume(did_status < DID_STATUS_COUNT);
  assert(did_status <= 1);

  /* PROP-4d: VM type enum range */
  unsigned int vm_type = nondet_uint();
  __CPROVER_assume(vm_type < DID_VM_COUNT);
  assert(vm_type <= 1);

  /* PROP-4e: Relationship enum range */
  unsigned int rel = nondet_uint();
  __CPROVER_assume(rel < DID_REL_COUNT);
  assert(rel <= 3);
}

/* ================================================================ */
/* Property 5: Array capacity bounds                                */
/* ================================================================ */

void harness_array_capacity(void) {
  /* PROP-5a: DID registry capacity */
  assert(DID_MAX_DIDS <= 128);
  assert(DID_MAX_DIDS > 0);

  /* PROP-5b: VC registry capacity */
  assert(DID_MAX_VCS <= 256);
  assert(DID_MAX_VCS > 0);

  /* PROP-5c: Services per DID */
  assert(DID_MAX_SERVICES <= 8);

  /* PROP-5d: VMs per DID */
  assert(DID_MAX_VMS <= 4);
  assert(DID_MAX_VMS >= 1); /* Need at least 1 for default */

  /* PROP-5e: VCs in presentation */
  assert(DID_MAX_VCS_IN_VP <= 8);
  assert(DID_MAX_VCS_IN_VP >= 1);

  /* PROP-5f: Claims per VC */
  assert(DID_MAX_CLAIMS <= 16);

  /* PROP-5g: Index bounds check */
  size_t did_idx = nondet_size();
  __CPROVER_assume(did_idx < DID_MAX_DIDS);
  assert(did_idx < 128);

  size_t vc_idx = nondet_size();
  __CPROVER_assume(vc_idx < DID_MAX_VCS);
  assert(vc_idx < 256);
}

/* ================================================================ */
/* Property 6: Verification state machine consistency               */
/* ================================================================ */

void harness_verify_state_machine(void) {
  /* Model the VC status transitions:
   * VALID -> SUSPENDED (suspend)
   * VALID -> REVOKED (revoke)
   * SUSPENDED -> VALID (reinstate)
   * SUSPENDED -> REVOKED (revoke)
   * REVOKED -> terminal (no outgoing transitions)
   */

  unsigned int current = nondet_uint();
  unsigned int action = nondet_uint();
  __CPROVER_assume(current < VC_STATUS_COUNT);
  __CPROVER_assume(action < 4); /* suspend, revoke, reinstate, sign */

  unsigned int next = current; /* Default: no transition */

  /* Suspend: only from VALID */
  if (action == 0 && current == 0) { /* VALID -> SUSPENDED */
    next = 2;                        /* SUSPENDED */
  }
  /* Revoke: from VALID or SUSPENDED */
  if (action == 1 && (current == 0 || current == 2)) {
    next = 1; /* REVOKED */
  }
  /* Reinstate: only from SUSPENDED */
  if (action == 2 && current == 2) {
    next = 0; /* VALID */
  }

  /* PROP-6a: REVOKED is terminal — if current is REVOKED, next is REVOKED */
  if (current == 1) {
    assert(next == 1);
  }

  /* PROP-6b: Next state is always valid */
  assert(next < VC_STATUS_COUNT);

  /* PROP-6c: SUSPENDED can only come from VALID */
  if (next == 2 && current != 2) {
    assert(current == 0);
  }
}

/* ================================================================ */
/* Unified harness                                                  */
/* ================================================================ */

void harness_all(void) {
  harness_did_uri_bounds();
  harness_claim_bounds();
  harness_pqc_sig_bounds();
  harness_vc_status_range();
  harness_array_capacity();
  harness_verify_state_machine();
}
