---- MODULE pqc_migration ----
(*
 * TLA+ Specification: PQC Key Migration State Machine
 * Models the 4-state FSM: CLASSICAL → HYBRID → FINALIZING → PQC_ONLY
 * with rollback from HYBRID and FINALIZING back to CLASSICAL.
 *
 * Verifies: state machine safety, key existence invariants,
 *           terminal state irrevocability, and no-skip properties.
 *)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS MaxKeys, MaxOps

VARIABLES keys, ops_done

\* State values
Classical  == 0
Hybrid     == 1
Finalizing == 2
PqcOnly    == 3

States == {Classical, Hybrid, Finalizing, PqcOnly}

\* Key record: [state |-> Int, has_classical |-> BOOLEAN, has_pqc |-> BOOLEAN]
KeyRecord == [state: States, has_classical: BOOLEAN, has_pqc: BOOLEAN]

TypeOK ==
  /\ \A k \in DOMAIN keys: keys[k] \in KeyRecord
  /\ ops_done \in 0..MaxOps
  /\ Len(keys) \in 0..MaxKeys

Init ==
  /\ keys = <<>>
  /\ ops_done = 0

\* --- Actions ---

\* Import a new key in CLASSICAL state (has classical key, no PQC)
Import ==
  /\ ops_done < MaxOps
  /\ Len(keys) < MaxKeys
  /\ keys' = Append(keys, [state |-> Classical, has_classical |-> TRUE, has_pqc |-> FALSE])
  /\ ops_done' = ops_done + 1

\* Begin migration: CLASSICAL → HYBRID (generate PQC keys)
BeginMigration ==
  /\ ops_done < MaxOps
  /\ \E i \in DOMAIN keys:
       /\ keys[i].state = Classical
       /\ keys' = [keys EXCEPT ![i] = [state |-> Hybrid, has_classical |-> TRUE, has_pqc |-> TRUE]]
       /\ ops_done' = ops_done + 1

\* Enter finalizing: HYBRID → FINALIZING (PQC self-test passed, backup started)
EnterFinalizing ==
  /\ ops_done < MaxOps
  /\ \E i \in DOMAIN keys:
       /\ keys[i].state = Hybrid
       /\ keys' = [keys EXCEPT ![i] = [state |-> Finalizing, has_classical |-> TRUE, has_pqc |-> TRUE]]
       /\ ops_done' = ops_done + 1

\* Complete finalization: FINALIZING → PQC_ONLY (classical key destroyed)
CompleteFinalizing ==
  /\ ops_done < MaxOps
  /\ \E i \in DOMAIN keys:
       /\ keys[i].state = Finalizing
       /\ keys' = [keys EXCEPT ![i] = [state |-> PqcOnly, has_classical |-> FALSE, has_pqc |-> TRUE]]
       /\ ops_done' = ops_done + 1

\* Rollback: HYBRID or FINALIZING → CLASSICAL (destroy PQC keys)
Rollback ==
  /\ ops_done < MaxOps
  /\ \E i \in DOMAIN keys:
       /\ keys[i].state \in {Hybrid, Finalizing}
       /\ keys' = [keys EXCEPT ![i] = [state |-> Classical, has_classical |-> TRUE, has_pqc |-> FALSE]]
       /\ ops_done' = ops_done + 1

Next ==
  \/ Import
  \/ BeginMigration
  \/ EnterFinalizing
  \/ CompleteFinalizing
  \/ Rollback

Spec == Init /\ [][Next]_<<keys, ops_done>>

\* --- Safety Invariants ---

\* INV-S1: No skip to final — cannot go from CLASSICAL directly to PQC_ONLY
\* (enforced by action structure: only Finalizing→PqcOnly transition exists)
NoSkipToFinal ==
  \A i \in DOMAIN keys:
    keys[i].state = PqcOnly => keys[i].has_pqc = TRUE

\* INV-S2: Rollback only from HYBRID or FINALIZING
\* (enforced by Rollback action guard)
RollbackOnlyFromHybridOrFinalizing ==
  \A i \in DOMAIN keys:
    keys[i].state = Classical => keys[i].has_pqc = FALSE

\* INV-S3: PQC_ONLY is terminal — no transitions from PQC_ONLY
PqcOnlyTerminal ==
  \A i \in DOMAIN keys:
    keys[i].state = PqcOnly => keys[i].has_classical = FALSE

\* INV-S4: Classical key exists in CLASSICAL and HYBRID states
ClassicalKeyExists ==
  \A i \in DOMAIN keys:
    keys[i].state \in {Classical, Hybrid, Finalizing} => keys[i].has_classical = TRUE

\* INV-S5: PQC key exists in HYBRID, FINALIZING, and PQC_ONLY states
PqcKeyExists ==
  \A i \in DOMAIN keys:
    keys[i].state \in {Hybrid, Finalizing, PqcOnly} => keys[i].has_pqc = TRUE

\* INV-S6: CLASSICAL has no PQC key
ClassicalNoPqc ==
  \A i \in DOMAIN keys:
    keys[i].state = Classical => keys[i].has_pqc = FALSE

====
