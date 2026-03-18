/**
 * wp_utxo.c — Frama-C/WP verification of UTXO double-spend prevention (INV-001)
 *
 * Models the core UTXO mark-spent logic with ACSL contracts.
 * Proves: no double-spend, state transition correctness, isolation.
 *
 * NOTE: parameter named 'uset' (not 'set') because 'set' is an ACSL keyword.
 *
 * Verify: frama-c -wp -wp-prover z3 -wp-timeout 60
 * verification/framac/wp_utxo.c
 */

typedef struct {
  unsigned long long amount;
  int spent;
} UTXO;

typedef struct {
  UTXO *entries;
  unsigned int count;
  unsigned int capacity;
} UTXOSet;

/* --- Core function: utxo_mark_spent (INV-001) --- */

/*@
  requires \valid(uset);
  requires uset->count > 0;
  requires uset->count <= uset->capacity;
  requires \valid(uset->entries + (0 .. uset->count - 1));
  requires idx < uset->count;

  assigns uset->entries[idx].spent;

  behavior already_spent:
    assumes uset->entries[idx].spent != 0;
    ensures \result == -200;
    ensures uset->entries[idx].spent == \old(uset->entries[idx].spent);
    assigns \nothing;

  behavior first_spend:
    assumes uset->entries[idx].spent == 0;
    ensures \result == 0;
    ensures uset->entries[idx].spent == 1;
    assigns uset->entries[idx].spent;

  complete behaviors;
  disjoint behaviors;
*/
int utxo_mark_spent_model(UTXOSet *uset, unsigned int idx) {
  UTXO *utxo = &uset->entries[idx];

  if (utxo->spent) {
    return -200;
  }

  utxo->spent = 1;
  return 0;
}

/* --- Isolation property: spending one UTXO doesn't affect others --- */

/*@
  requires \valid(uset);
  requires uset->count >= 2;
  requires uset->count <= uset->capacity;
  requires \valid(uset->entries + (0 .. uset->count - 1));
  requires idx1 < uset->count;
  requires idx2 < uset->count;
  requires idx1 != idx2;

  assigns uset->entries[idx1].spent;

  ensures uset->entries[idx2].spent == \old(uset->entries[idx2].spent);
  ensures uset->entries[idx2].amount == \old(uset->entries[idx2].amount);
*/
int utxo_spend_isolation(UTXOSet *uset, unsigned int idx1, unsigned int idx2) {
  return utxo_mark_spent_model(uset, idx1);
}

/* --- NULL-safe wrapper --- */

/*@
  behavior null_input:
    assumes uset == \null;
    ensures \result == -200;
    assigns \nothing;

  behavior out_of_bounds:
    assumes uset != \null;
    assumes uset->entries != \null;
    assumes idx >= uset->count;
    ensures \result == -200;
    assigns \nothing;

  behavior valid_unspent:
    assumes uset != \null;
    assumes uset->entries != \null;
    assumes uset->count > 0;
    assumes idx < uset->count;
    assumes \valid(uset->entries + (0 .. uset->count - 1));
    assumes uset->entries[idx].spent == 0;
    ensures \result == 0;
    ensures uset->entries[idx].spent == 1;
    assigns uset->entries[idx].spent;

  behavior valid_spent:
    assumes uset != \null;
    assumes uset->entries != \null;
    assumes uset->count > 0;
    assumes idx < uset->count;
    assumes \valid(uset->entries + (0 .. uset->count - 1));
    assumes uset->entries[idx].spent != 0;
    ensures \result == -200;
    assigns \nothing;
*/
int utxo_mark_spent_safe(UTXOSet *uset, unsigned int idx) {
  if (!uset || !uset->entries)
    return -200;

  if (idx >= uset->count)
    return -200;

  UTXO *utxo = &uset->entries[idx];

  if (utxo->spent) {
    return -200;
  }

  utxo->spent = 1;
  return 0;
}
