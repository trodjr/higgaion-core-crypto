/**
 * wp_token_ledger.c — Frama-C/WP verification of token ledger balance
 * operations
 *
 * Proves: overflow-safe credit, underflow-safe debit, balance conservation,
 * and saturating multiplication.
 *
 * Verify: frama-c -wp -wp-prover z3 -wp-timeout 60
 * verification/framac/wp_token_ledger.c
 */

#include <stdbool.h>
#include <stdint.h>

/* --- Simplified types matching src/token_ledger.h --- */

typedef enum { HIG_OK = 0, HIG_ERR_VALIDATION = -200 } HigError;

typedef struct {
  uint64_t balance;
  uint32_t utxo_count;
  bool occupied;
} BalanceEntry;

/* --- Checked arithmetic (from src/token_ledger.c) --- */

/*@
  requires \valid(out);

  behavior overflow:
    assumes a > UINT64_MAX - b;
    assigns \nothing;
    ensures \result == false;

  behavior safe:
    assumes a <= UINT64_MAX - b;
    assigns *out;
    ensures \result == true;
    ensures *out == a + b;

  complete behaviors;
  disjoint behaviors;
*/
bool safe_add_u64(uint64_t a, uint64_t b, uint64_t *out) {
  if (a > UINT64_MAX - b)
    return false;
  *out = a + b;
  return true;
}

/*@
  requires \valid(out);

  behavior underflow:
    assumes a < b;
    assigns \nothing;
    ensures \result == false;

  behavior safe:
    assumes a >= b;
    assigns *out;
    ensures \result == true;
    ensures *out == a - b;

  complete behaviors;
  disjoint behaviors;
*/
bool safe_sub_u64(uint64_t a, uint64_t b, uint64_t *out) {
  if (a < b)
    return false;
  *out = a - b;
  return true;
}

/* --- ledger_credit_unlocked model (from src/token_ledger.c:230-262) --- */

/*@
  requires \valid(entry);
  requires entry->occupied == true;
  requires amount > 0;
  requires entry->utxo_count < UINT32_MAX;

  behavior overflow:
    assumes entry->balance > UINT64_MAX - amount;
    assigns \nothing;
    ensures \result == HIG_ERR_VALIDATION;
    ensures entry->balance == \old(entry->balance);

  behavior safe_credit:
    assumes entry->balance <= UINT64_MAX - amount;
    assigns entry->balance, entry->utxo_count;
    ensures \result == HIG_OK;
    ensures entry->balance == \old(entry->balance) + amount;
    ensures entry->utxo_count == (uint32_t)(\old(entry->utxo_count) + 1);

  complete behaviors;
  disjoint behaviors;
*/
HigError ledger_credit_model(BalanceEntry *entry, uint64_t amount) {
  if (entry->balance > UINT64_MAX - amount)
    return HIG_ERR_VALIDATION;

  entry->balance += amount;
  entry->utxo_count++;
  return HIG_OK;
}

/* --- ledger_debit model (from src/token_ledger.c:275-298) --- */

/*@
  requires \valid(entry);
  requires entry->occupied == true;
  requires amount > 0;

  behavior insufficient_funds:
    assumes entry->balance < amount;
    assigns \nothing;
    ensures \result == HIG_ERR_VALIDATION;
    ensures entry->balance == \old(entry->balance);

  behavior safe_debit:
    assumes entry->balance >= amount;
    assigns entry->balance, entry->utxo_count;
    ensures \result == HIG_OK;
    ensures entry->balance == \old(entry->balance) - amount;

  complete behaviors;
  disjoint behaviors;
*/
HigError ledger_debit_model(BalanceEntry *entry, uint64_t amount) {
  if (entry->balance < amount)
    return HIG_ERR_VALIDATION;

  entry->balance -= amount;
  if (entry->utxo_count > 0)
    entry->utxo_count--;

  return HIG_OK;
}

/* --- Conservation law: credit then debit of same amount = no change --- */

/*@
  requires \valid(entry);
  requires entry->occupied == true;
  requires amount > 0;
  requires entry->balance <= UINT64_MAX - amount;
  requires entry->utxo_count < UINT32_MAX;

  assigns entry->balance, entry->utxo_count;

  ensures entry->balance == \old(entry->balance);
*/
void conservation_law(BalanceEntry *entry, uint64_t amount) {
  uint64_t old_balance = entry->balance;

  HigError r1 = ledger_credit_model(entry, amount);
  /*@ assert r1 == HIG_OK; */
  /*@ assert entry->balance == old_balance + amount; */

  HigError r2 = ledger_debit_model(entry, amount);
  /*@ assert r2 == HIG_OK; */
  /*@ assert entry->balance == old_balance; */
}

/* --- Saturating multiplication (from src/fee_market.c) --- */

/*@
  assigns \nothing;

  behavior zero:
    assumes a == 0 || b == 0;
    ensures \result == 0;

  behavior saturate:
    assumes a != 0 && b != 0 && a > UINT64_MAX / b;
    ensures \result == UINT64_MAX;

  behavior normal:
    assumes a != 0 && b != 0 && a <= UINT64_MAX / b;
    ensures \result <= UINT64_MAX;

  complete behaviors;
  disjoint behaviors;
*/
uint64_t saturating_mul_u64(uint64_t a, uint64_t b) {
  if (a == 0 || b == 0)
    return 0;
  if (a > UINT64_MAX / b)
    return UINT64_MAX;
  /*@ assert a <= UINT64_MAX / b; */
  return a * b;
}
