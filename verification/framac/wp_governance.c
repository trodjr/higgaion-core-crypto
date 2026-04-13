/**
 * wp_governance.c — Frama-C/WP verification of governance vote casting
 *
 * Proves: no double-voting, vote weight accumulation correctness,
 * quorum floor enforcement.
 *
 * NOTE: Uses manual byte comparison instead of memcmp() to avoid
 * Frama-C WP modelling limitations with libc string functions.
 *
 * Verify: frama-c -wp -wp-prover z3 -wp-timeout 60
 * verification/framac/wp_governance.c
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* --- Simplified types matching src/governance.h --- */

#define GOV_PK_HASH_SIZE 32

typedef enum { HIG_OK = 0, HIG_ERR_VALIDATION = -200 } HigError;

typedef enum {
  GOV_VOTE_FOR = 0,
  GOV_VOTE_AGAINST = 1,
  GOV_VOTE_ABSTAIN = 2
} GovVoteChoice;

typedef struct {
  uint8_t voter_pk_hash[GOV_PK_HASH_SIZE];
  GovVoteChoice choice;
  uint64_t weight;
} GovVote;

typedef struct {
  GovVote *votes;
  size_t vote_count;
  size_t vote_capacity;
  uint64_t votes_for;
  uint64_t votes_against;
  uint64_t votes_abstain;
  uint64_t total_stake;
} GovProposal;

/* --- Manual byte comparison (replaces memcmp to avoid WP libc issues) --- */

/*@
  requires \valid_read(a + (0 .. GOV_PK_HASH_SIZE - 1));
  requires \valid_read(b + (0 .. GOV_PK_HASH_SIZE - 1));

  assigns \nothing;

  behavior equal:
    assumes \forall integer k; 0 <= k < GOV_PK_HASH_SIZE ==> a[k] == b[k];
    ensures \result == true;

  behavior different:
    assumes \exists integer k; 0 <= k < GOV_PK_HASH_SIZE && a[k] != b[k];
    ensures \result == false;

  complete behaviors;
  disjoint behaviors;
*/
static bool pk_equal(const uint8_t *a, const uint8_t *b) {
  /*@
    loop invariant 0 <= i <= GOV_PK_HASH_SIZE;
    loop invariant \forall integer k; 0 <= k < i ==> a[k] == b[k];
    loop assigns i;
    loop variant GOV_PK_HASH_SIZE - i;
  */
  for (int i = 0; i < GOV_PK_HASH_SIZE; i++) {
    if (a[i] != b[i])
      return false;
  }
  return true;
}

/* --- has_voted (from src/governance.c:30-40) --- */

/*@
  requires \valid(p);
  requires p->vote_count <= p->vote_capacity;
  requires \valid_read(p->votes + (0 .. p->vote_count - 1));
  requires p->vote_count > 0;
  requires \valid_read(pk_hash + (0 .. GOV_PK_HASH_SIZE - 1));

  assigns \nothing;

  behavior found:
    assumes \exists integer i; 0 <= i < p->vote_count &&
            \forall integer k; 0 <= k < GOV_PK_HASH_SIZE ==>
            p->votes[i].voter_pk_hash[k] == pk_hash[k];
    ensures \result == true;

  behavior not_found:
    assumes \forall integer i; 0 <= i < p->vote_count ==>
            \exists integer k; 0 <= k < GOV_PK_HASH_SIZE &&
            p->votes[i].voter_pk_hash[k] != pk_hash[k];
    ensures \result == false;

  complete behaviors;
  disjoint behaviors;
*/
static bool has_voted(const GovProposal *p, const uint8_t *pk_hash) {
  /*@
    loop invariant 0 <= i <= p->vote_count;
    loop invariant \forall integer j; 0 <= j < i ==>
        \exists integer k; 0 <= k < GOV_PK_HASH_SIZE &&
        p->votes[j].voter_pk_hash[k] != pk_hash[k];
    loop assigns i;
    loop variant p->vote_count - i;
  */
  for (size_t i = 0; i < p->vote_count; i++) {
    if (pk_equal(p->votes[i].voter_pk_hash, pk_hash))
      return true;
  }
  return false;
}

/* --- Vote weight accumulation model --- */

/*@
  requires \valid(p);
  requires choice == GOV_VOTE_FOR || choice == GOV_VOTE_AGAINST || choice ==
  GOV_VOTE_ABSTAIN; requires weight > 0;

  behavior vote_for:
    assumes choice == GOV_VOTE_FOR;
    assumes p->votes_for <= UINT64_MAX - weight;
    assigns p->votes_for;
    ensures p->votes_for == \old(p->votes_for) + weight;
    ensures p->votes_against == \old(p->votes_against);
    ensures p->votes_abstain == \old(p->votes_abstain);

  behavior vote_against:
    assumes choice == GOV_VOTE_AGAINST;
    assumes p->votes_against <= UINT64_MAX - weight;
    assigns p->votes_against;
    ensures p->votes_against == \old(p->votes_against) + weight;
    ensures p->votes_for == \old(p->votes_for);
    ensures p->votes_abstain == \old(p->votes_abstain);

  behavior vote_abstain:
    assumes choice == GOV_VOTE_ABSTAIN;
    assumes p->votes_abstain <= UINT64_MAX - weight;
    assigns p->votes_abstain;
    ensures p->votes_abstain == \old(p->votes_abstain) + weight;
    ensures p->votes_for == \old(p->votes_for);
    ensures p->votes_against == \old(p->votes_against);

  disjoint behaviors;
*/
void accumulate_vote(GovProposal *p, GovVoteChoice choice, uint64_t weight) {
  /*@ assert choice == 0 || choice == 1 || choice == 2; */
  switch (choice) {
  case GOV_VOTE_FOR:
    p->votes_for += weight;
    break;
  case GOV_VOTE_AGAINST:
    p->votes_against += weight;
    break;
  case GOV_VOTE_ABSTAIN:
    p->votes_abstain += weight;
    break;
  }
}

/* --- Quorum check (10% floor, from gov_tally) --- */

/*@
  requires total_stake > 0;
  assigns \nothing;
  ensures \result == true <==> total_votes >= total_stake / 10 + 1;
*/
bool quorum_reached(uint64_t total_votes, uint64_t total_stake) {
  if (total_stake == 0)
    return false;
  return total_votes >= (total_stake / 10 + 1);
}

/* --- Approval threshold (67%, from gov_tally) --- */

/*@
  requires total_votes > 0;
  requires votes_for <= total_votes;
  requires total_votes <= UINT64_MAX / 100;

  assigns \nothing;

  ensures \result == true <==> 100 * votes_for >= 67 * total_votes;
*/
bool approval_reached(uint64_t votes_for, uint64_t total_votes) {
  if (total_votes == 0)
    return false;
  return (votes_for * 100) >= (total_votes * 67);
}
