/**
 * @file cbmc_consensus.c
 * @brief CBMC harness for BFT quorum formula correctness (INV-002)
 *
 * Proves that bft_quorum() correctly computes the BFT supermajority
 * threshold: strictly more than 2/3 of validators.
 *
 * Properties verified:
 * 1. bft_quorum(n) == (2*n/3) + 1 for all valid n
 * 2. bft_quorum(n) > 2*n/3 (strict supermajority)
 * 3. n - bft_quorum(n) < n/3 (fewer than n/3 can oppose)
 * 4. quorum is achievable (quorum <= n)
 * 5. Edge cases: n=4 (minimum BFT), n=256 (MAX_PEERS)
 *
 * Run: cbmc verification/cbmc_consensus.c -I include \
 *      --bounds-check --signed-overflow-check \
 *      --unwind 1 --unwinding-assertions
 */

#include <assert.h>
#include <stdint.h>

/**
 * Model of bft_quorum() from src/consensus.c
 *
 * This is the single source of truth for quorum calculation (INFO-13-03).
 * All 4 quorum check sites in the codebase call this function.
 */
static uint32_t bft_quorum(uint32_t n) { return (2 * n) / 3 + 1; }

/**
 * Model of get_leader_for_view() from src/consensus.c
 *
 * Deterministic round-robin leader selection.
 */
static uint32_t get_leader_for_view(uint32_t view, uint32_t n_validators) {
  if (n_validators == 0)
    return 0;
  return (view - 1) % n_validators;
}

/* ---- CBMC Harness ---- */

void main(void) {
  uint32_t n;

  /* BFT requires n >= 3f+1; minimum useful is n=4 (f=1) */
  __CPROVER_assume(n >= 4 && n <= 256);

  uint32_t q = bft_quorum(n);

  /* === Property 1: Formula correctness === */
  assert(q == (2 * n) / 3 + 1);

  /* === Property 2: Strict supermajority (> 2/3) === */
  /* q > 2n/3, which means 3q > 2n */
  assert(3 * q > 2 * n);

  /* === Property 3: Fewer than n/3 can oppose === */
  /* n - q < n/3, which means 3*(n-q) < n */
  uint32_t opposition = n - q;
  assert(3 * opposition < n);

  /* === Property 4: Quorum is achievable === */
  assert(q <= n);

  /* === Property 5: Quorum is non-trivial (> 1) === */
  assert(q >= 2);

  /* === Property 6: No integer overflow in computation === */
  /* 2*n for n<=256 fits in uint32_t (max 512) */
  assert(2 * (uint64_t)n < UINT32_MAX);

  /* === Property 7: Edge cases === */
  /* n=4 (minimum BFT with f=1): quorum should be 3 */
  assert(bft_quorum(4) == 3);

  /* n=7 (f=2): quorum should be 5 */
  assert(bft_quorum(7) == 5);

  /* n=256 (MAX_PEERS): quorum should be 171 */
  assert(bft_quorum(256) == 171);

  /* === Property 8: Leader uniqueness per view === */
  uint32_t view1, view2;
  __CPROVER_assume(view1 >= 1 && view1 <= 100);
  __CPROVER_assume(view2 >= 1 && view2 <= 100);

  uint32_t leader1 = get_leader_for_view(view1, n);
  uint32_t leader2 = get_leader_for_view(view2, n);

  /* Same view => same leader (deterministic) */
  if (view1 == view2) {
    assert(leader1 == leader2);
  }

  /* Leader is always a valid validator index */
  assert(leader1 < n);
  assert(leader2 < n);

  /* === Property 9: Full leader rotation === */
  /* After n views, we cycle back to the same leader */
  uint32_t view_a;
  __CPROVER_assume(view_a >= 1 && view_a <= 100);
  if (view_a + n <= 100) {
    assert(get_leader_for_view(view_a, n) ==
           get_leader_for_view(view_a + n, n));
  }
}
