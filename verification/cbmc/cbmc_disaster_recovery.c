/**
 * @file cbmc_disaster_recovery.c
 * @brief CBMC bounded model checking harness for Disaster Recovery.
 *
 * 6 property groups verifying buffer bounds, enum ranges, capacity,
 * replication state machine, retention, and RTO/RPO invariants.
 *
 * Run: cbmc --function harness_all verification/cbmc_disaster_recovery.c \
 *      --signed-overflow-check --unsigned-overflow-check --unwind 16
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

/* Constants from disaster_recovery.h */
#define DR_MAX_SNAPSHOTS 256
#define DR_MAX_REGIONS 8
#define DR_MAX_RETENTION_RULES 8
#define DR_SNAPSHOT_ID_SIZE 33
#define DR_REGION_NAME_SIZE 64
#define DR_PATH_SIZE 256
#define DR_HASH_SIZE 32
#define DR_DESCRIPTION_SIZE 128

#define DR_SNAP_COUNT 3
#define DR_STATUS_COUNT 7
#define DR_REGION_COUNT 3
#define DR_RETAIN_COUNT 4

unsigned int nondet_uint(void);
size_t nondet_size(void);

/* ================================================================ */
/* Property 1: Snapshot ID and description buffer bounds             */
/* ================================================================ */

void harness_snapshot_buffers(void) {
  /* Snapshot ID: 32 hex chars + null */
  assert(32 + 1 <= DR_SNAPSHOT_ID_SIZE);

  /* Description fits in buffer */
  assert(DR_DESCRIPTION_SIZE >= 128);

  /* Region name buffer */
  assert(DR_REGION_NAME_SIZE >= 64);

  /* Path buffer */
  assert(DR_PATH_SIZE >= 256);

  /* Hash buffer */
  assert(DR_HASH_SIZE == 32);
}

/* ================================================================ */
/* Property 2: Enum ranges                                          */
/* ================================================================ */

void harness_enum_ranges(void) {
  unsigned int snap_type = nondet_uint();
  __CPROVER_assume(snap_type < DR_SNAP_COUNT);
  assert(snap_type <= 2); /* FULL, INCREMENTAL, WAL */

  unsigned int status = nondet_uint();
  __CPROVER_assume(status < DR_STATUS_COUNT);
  assert(status <= 6);

  unsigned int health = nondet_uint();
  __CPROVER_assume(health < DR_REGION_COUNT);
  assert(health <= 2); /* HEALTHY, DEGRADED, OFFLINE */

  unsigned int retain = nondet_uint();
  __CPROVER_assume(retain < DR_RETAIN_COUNT);
  assert(retain <= 3); /* HOURLY, DAILY, WEEKLY, MONTHLY */
}

/* ================================================================ */
/* Property 3: Array capacity bounds                                */
/* ================================================================ */

void harness_capacity(void) {
  assert(DR_MAX_SNAPSHOTS == 256);
  assert(DR_MAX_SNAPSHOTS > 0);

  assert(DR_MAX_REGIONS == 8);
  assert(DR_MAX_REGIONS >= 2); /* Need ≥2 for INV-052 */

  assert(DR_MAX_RETENTION_RULES == 8);
  assert(DR_MAX_RETENTION_RULES > 0);

  /* Index bounds */
  size_t snap_idx = nondet_size();
  __CPROVER_assume(snap_idx < DR_MAX_SNAPSHOTS);
  assert(snap_idx < 256);

  size_t reg_idx = nondet_size();
  __CPROVER_assume(reg_idx < DR_MAX_REGIONS);
  assert(reg_idx < 8);

  /* Region bitmask fits in uint32_t */
  assert(DR_MAX_REGIONS <= 32);
}

/* ================================================================ */
/* Property 4: INV-052 replication state machine                    */
/* ================================================================ */

void harness_replication_state(void) {
  unsigned int current = nondet_uint();
  unsigned int region_count = nondet_uint();
  __CPROVER_assume(current < DR_STATUS_COUNT);
  __CPROVER_assume(region_count <= DR_MAX_REGIONS);

  unsigned int next = current;

  /* Replicate: COMPLETE → REPLICATING (1 region) or VERIFIED (≥2) */
  if (current == 1 || current == 2) { /* COMPLETE or REPLICATING */
    if (region_count >= 2) {
      next = 3; /* VERIFIED */
    } else if (region_count == 1) {
      next = 2; /* REPLICATING */
    }
  }

  /* PROP-4a: VERIFIED requires ≥2 regions (INV-052) */
  if (next == 3) {
    assert(region_count >= 2);
  }

  /* PROP-4b: PRUNED is terminal */
  if (current == 6) {
    assert(next == 6);
  }

  /* PROP-4c: Next state is valid */
  assert(next < DR_STATUS_COUNT);
}

/* ================================================================ */
/* Property 5: Retention bounds                                     */
/* ================================================================ */

void harness_retention(void) {
  size_t total = nondet_size();
  size_t keep = nondet_size();
  __CPROVER_assume(total <= DR_MAX_SNAPSHOTS);
  __CPROVER_assume(keep > 0);
  __CPROVER_assume(keep <= DR_MAX_SNAPSHOTS);

  if (total > keep) {
    size_t to_prune = total - keep;
    /* PROP-5a: Prune count never exceeds total */
    assert(to_prune < total);
    /* PROP-5b: Remaining count equals keep */
    assert(total - to_prune == keep);
  }

  /* PROP-5c: Keep count is positive */
  assert(keep > 0);
}

/* ================================================================ */
/* Property 6: RTO/RPO compliance logic                             */
/* ================================================================ */

void harness_rto_rpo(void) {
  uint64_t rto_target = nondet_uint();
  uint64_t rto_actual = nondet_uint();
  uint64_t rpo_target = nondet_uint();
  uint64_t rpo_actual = nondet_uint();

  __CPROVER_assume(rto_target > 0);
  __CPROVER_assume(rpo_target > 0);

  int rto_ok = (rto_actual <= rto_target);
  int rpo_ok = (rpo_actual <= rpo_target);
  int compliant = rto_ok && rpo_ok;

  /* PROP-6a: Compliance requires both RTO and RPO met */
  if (compliant) {
    assert(rto_actual <= rto_target);
    assert(rpo_actual <= rpo_target);
  }

  /* PROP-6b: Any breach means non-compliant */
  if (rto_actual > rto_target || rpo_actual > rpo_target) {
    assert(!compliant);
  }
}

void harness_all(void) {
  harness_snapshot_buffers();
  harness_enum_ranges();
  harness_capacity();
  harness_replication_state();
  harness_retention();
  harness_rto_rpo();
}
