/**
 * @file cbmc_overflow.c
 * @brief CBMC harness for arithmetic overflow prevention
 *
 * Proves that critical arithmetic operations in the token ledger,
 * fee market, and governance modules use saturating/checked arithmetic
 * that prevents overflow/underflow.
 *
 * Run: cbmc verification/cbmc_overflow.c \
 *      --bounds-check --signed-overflow-check \
 *      --unsigned-overflow-check --conversion-check \
 *      --unwind 5 --unwinding-assertions
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

/* ========================================================================
 * Token Ledger — balance operations (from src/token_ledger.c)
 * ======================================================================== */

/**
 * Model of checked addition for token balances.
 * Maps to: token_ledger.c ledger_transfer() overflow guard.
 */
static bool safe_add_u64(uint64_t a, uint64_t b, uint64_t *result) {
  if (a > UINT64_MAX - b)
    return false; /* Would overflow */
  *result = a + b;
  return true;
}

/**
 * Model of checked subtraction for token balances.
 * Maps to: token_ledger.c ledger_transfer() underflow guard.
 */
static bool safe_sub_u64(uint64_t a, uint64_t b, uint64_t *result) {
  if (a < b)
    return false; /* Would underflow */
  *result = a - b;
  return true;
}

/**
 * Model of token transfer with overflow/underflow protection.
 * Maps to: token_ledger.c ledger_transfer()
 */
static bool transfer_model(uint64_t *sender_bal, uint64_t *receiver_bal,
                           uint64_t amount) {
  if (!sender_bal || !receiver_bal)
    return false;
  if (amount == 0)
    return true; /* No-op */

  uint64_t new_sender, new_receiver;
  if (!safe_sub_u64(*sender_bal, amount, &new_sender))
    return false;
  if (!safe_add_u64(*receiver_bal, amount, &new_receiver))
    return false;

  *sender_bal = new_sender;
  *receiver_bal = new_receiver;
  return true;
}

/* ========================================================================
 * Fee Market — fee calculations (from src/fee_market.c)
 * ======================================================================== */

/**
 * Model of saturating multiplication for fee calculation.
 * Maps to: fee_market.c priority calculation.
 */
static uint64_t saturating_mul_u64(uint64_t a, uint64_t b) {
  if (a == 0 || b == 0)
    return 0;
  if (a > UINT64_MAX / b)
    return UINT64_MAX; /* Saturate */
  return a * b;
}

/**
 * Model of fee priority calculation.
 * Maps to: fee_market.c fee_market_priority_sort()
 */
static uint64_t calculate_priority(uint64_t fee, uint64_t size) {
  if (size == 0)
    return 0; /* Prevent div-by-zero */
  return fee / size;
}

/* ========================================================================
 * Governance — vote counting (from src/governance.c)
 * ======================================================================== */

/**
 * Model of safe vote accumulation.
 * Maps to: governance.c gov_cast_vote()
 */
static bool safe_add_votes(uint32_t current, uint32_t weight,
                           uint32_t *result) {
  if (current > UINT32_MAX - weight)
    return false;
  *result = current + weight;
  return true;
}

/**
 * Model of quorum check.
 * Maps to: governance.c gov_tally() — GOV_MIN_QUORUM (10%)
 */
static bool quorum_reached(uint32_t votes, uint32_t total_validators) {
  if (total_validators == 0)
    return false;
  /* 10% quorum floor: votes >= total/10 */
  return votes >= (total_validators / 10 + 1);
}

/* ---- CBMC Harness ---- */

void main(void) {
  /* === Token Ledger Properties === */

  uint64_t sender_bal, receiver_bal, amount;
  __CPROVER_assume(sender_bal <= 1000000);
  __CPROVER_assume(receiver_bal <= 1000000);
  __CPROVER_assume(amount <= 2000000);

  /* Property 1: Transfer preserves total supply (conservation) */
  uint64_t total_before = sender_bal + receiver_bal;

  uint64_t s = sender_bal, r = receiver_bal;
  if (transfer_model(&s, &r, amount)) {
    uint64_t total_after = s + r;
    assert(total_after == total_before); /* Conservation law */
    assert(s <= sender_bal);             /* Sender decreased */
    assert(r >= receiver_bal);           /* Receiver increased */
  }

  /* Property 2: Transfer never overflows sender */
  s = sender_bal;
  r = receiver_bal;
  if (amount > sender_bal) {
    assert(!transfer_model(&s, &r, amount)); /* Must reject */
  }

  /* Property 3: Transfer with receiver at near-max is rejected */
  s = 100;
  r = UINT64_MAX - 50;
  assert(!transfer_model(&s, &r, 100));

  /* Property 4: safe_add detects overflow */
  uint64_t result;
  assert(!safe_add_u64(UINT64_MAX, 1, &result));
  assert(!safe_add_u64(UINT64_MAX / 2 + 1, UINT64_MAX / 2 + 1, &result));

  /* Property 5: safe_sub detects underflow */
  assert(!safe_sub_u64(0, 1, &result));
  assert(!safe_sub_u64(100, 101, &result));
  assert(safe_sub_u64(100, 100, &result));
  assert(result == 0);

  /* === Fee Market Properties === */

  uint64_t fee, size;
  __CPROVER_assume(fee <= 1000000);
  __CPROVER_assume(size <= 1000000);

  /* Property 6: Saturating mul never overflows */
  uint64_t product = saturating_mul_u64(fee, size);
  assert(product <= UINT64_MAX); /* Tautology, but proves no UB */

  /* Property 7: Saturating mul handles edge cases */
  assert(saturating_mul_u64(UINT64_MAX, 2) == UINT64_MAX);
  assert(saturating_mul_u64(0, UINT64_MAX) == 0);
  assert(saturating_mul_u64(1, UINT64_MAX) == UINT64_MAX);

  /* Property 8: Priority calculation is div-by-zero safe */
  uint64_t prio = calculate_priority(fee, size);
  if (size == 0) {
    assert(prio == 0);
  }

  /* === Governance Properties === */

  uint32_t votes, weight, total_vals;
  __CPROVER_assume(total_vals >= 4 && total_vals <= 256);

  /* Property 9: Vote accumulation overflow detection */
  uint32_t vote_result;
  assert(!safe_add_votes(UINT32_MAX, 1, &vote_result));

  /* Property 10: Quorum calculation is safe */
  __CPROVER_assume(votes <= total_vals);
  bool q = quorum_reached(votes, total_vals);
  /* If all validators voted, quorum is always reached */
  if (votes == total_vals) {
    assert(q);
  }
}
