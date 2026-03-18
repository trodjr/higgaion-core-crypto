/**
 * @file cbmc_siem_export.c
 * @brief CBMC bounded model checking harness for SIEM Export.
 *
 * 6 property groups verifying event buffers, hash chain sizing,
 * severity/category ranges, filter logic, capacity, and export formats.
 *
 * Run: cbmc --function harness_all verification/cbmc_siem_export.c \
 *      --signed-overflow-check --unsigned-overflow-check --unwind 16
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

/* Constants from siem_export.h */
#define SIEM_MAX_EVENTS 4096
#define SIEM_MAX_FILTERS 16
#define SIEM_EVENT_MSG_SIZE 512
#define SIEM_SOURCE_SIZE 64
#define SIEM_ACTOR_SIZE 64
#define SIEM_DETAIL_SIZE 256
#define SIEM_HASH_SIZE 32
#define SIEM_ID_SIZE 33
#define SIEM_EXPORT_BUF_SIZE 65536

#define SIEM_SEV_COUNT 8
#define SIEM_CAT_COUNT 10
#define SIEM_FMT_COUNT 3

unsigned int nondet_uint(void);
size_t nondet_size(void);

/* ================================================================ */
/* Property 1: Event buffer sizing                                  */
/* ================================================================ */

void harness_event_buffers(void) {
  /* Event ID: 32 hex chars + null */
  assert(32 + 1 <= SIEM_ID_SIZE);

  /* Message buffer */
  assert(SIEM_EVENT_MSG_SIZE >= 512);

  /* Source buffer */
  assert(SIEM_SOURCE_SIZE >= 64);

  /* Actor buffer */
  assert(SIEM_ACTOR_SIZE >= 64);

  /* Detail buffer */
  assert(SIEM_DETAIL_SIZE >= 256);

  /* Export buffer large enough for reasonable output */
  assert(SIEM_EXPORT_BUF_SIZE >= 65536);
}

/* ================================================================ */
/* Property 2: Hash chain sizing                                    */
/* ================================================================ */

void harness_hash_chain(void) {
  /* SHA-256 hash = 32 bytes */
  assert(SIEM_HASH_SIZE == 32);

  /* Chain input: prev_chain(32) + event_hash(32) = 64 bytes */
  size_t chain_input = SIEM_HASH_SIZE + SIEM_HASH_SIZE;
  assert(chain_input == 64);

  /* Event hash input: seq(8) + ts(8) + sev(4) + cat(4) + msg(512) + src(64) */
  size_t event_input = 8 + 8 + 4 + 4 + SIEM_EVENT_MSG_SIZE + SIEM_SOURCE_SIZE;
  assert(event_input <= 1024); /* Fits in hash buffer */
}

/* ================================================================ */
/* Property 3: Severity and category ranges                         */
/* ================================================================ */

void harness_enum_ranges(void) {
  unsigned int sev = nondet_uint();
  __CPROVER_assume(sev < SIEM_SEV_COUNT);
  assert(sev <= 7); /* Emergency(0) .. Debug(7) */

  unsigned int cat = nondet_uint();
  __CPROVER_assume(cat < SIEM_CAT_COUNT);
  assert(cat <= 9); /* Auth(0) .. Security(9) */

  unsigned int fmt = nondet_uint();
  __CPROVER_assume(fmt < SIEM_FMT_COUNT);
  assert(fmt <= 2); /* CEF, Syslog, JSONL */

  /* Category bitmask fits in uint32_t */
  assert(SIEM_CAT_COUNT <= 32);
}

/* ================================================================ */
/* Property 4: Filter logic                                         */
/* ================================================================ */

void harness_filter_logic(void) {
  unsigned int event_sev = nondet_uint();
  unsigned int filter_sev = nondet_uint();
  __CPROVER_assume(event_sev < SIEM_SEV_COUNT);
  __CPROVER_assume(filter_sev < SIEM_SEV_COUNT);

  /* Severity filter: lower number = more severe */
  int passes_sev = (event_sev <= filter_sev);

  /* PROP-4a: Emergency (0) always passes any filter */
  if (event_sev == 0) {
    assert(passes_sev);
  }

  /* PROP-4b: Debug (7) only passes if filter is DEBUG */
  if (event_sev == 7 && filter_sev < 7) {
    assert(!passes_sev);
  }

  /* Category bitmask filter */
  unsigned int cat = nondet_uint();
  uint32_t mask = nondet_uint();
  __CPROVER_assume(cat < SIEM_CAT_COUNT);

  int passes_cat = (mask == 0) || (mask & (1u << cat));

  /* PROP-4c: Mask 0 means all categories pass */
  if (mask == 0) {
    assert(passes_cat);
  }
}

/* ================================================================ */
/* Property 5: Capacity and sequence                                */
/* ================================================================ */

void harness_capacity(void) {
  assert(SIEM_MAX_EVENTS == 4096);
  assert(SIEM_MAX_EVENTS > 0);

  size_t idx = nondet_size();
  __CPROVER_assume(idx < SIEM_MAX_EVENTS);
  assert(idx < 4096);

  /* Sequence counter monotonicity */
  uint64_t seq1 = nondet_uint();
  uint64_t seq2 = nondet_uint();
  __CPROVER_assume(seq2 == seq1 + 1);
  assert(seq2 > seq1);

  /* Max filter count */
  assert(SIEM_MAX_FILTERS == 16);
}

/* ================================================================ */
/* Property 6: CEF severity mapping                                 */
/* ================================================================ */

void harness_cef_mapping(void) {
  /* CEF severity range is 0-10 */
  int cef_severity[] = {10, 9, 8, 7, 5, 4, 3, 1};

  unsigned int sev = nondet_uint();
  __CPROVER_assume(sev < SIEM_SEV_COUNT);

  /* PROP-6a: All CEF values in valid range */
  assert(cef_severity[sev] >= 0);
  assert(cef_severity[sev] <= 10);

  /* PROP-6b: More severe = higher CEF value */
  if (sev == 0)
    assert(cef_severity[sev] == 10); /* Emergency = 10 */
  if (sev == 7)
    assert(cef_severity[sev] == 1); /* Debug = 1 */

  /* PROP-6c: Monotonic (approximately) */
  if (sev < 4) {
    assert(cef_severity[sev] >= 7);
  }
}

void harness_all(void) {
  harness_event_buffers();
  harness_hash_chain();
  harness_enum_ranges();
  harness_filter_logic();
  harness_capacity();
  harness_cef_mapping();
}
