(* =========================================================================
   HiggaionTypes.v — Shared Type Universe for Higgaion Protocol Models

   Abstract types and definitions used across all Coq proofs.
   This is NOT a translation of C source code — it defines the
   mathematical objects (validators, phases, states) used to state
   and prove protocol theorems.

   Maps to: src/pqc_crypto.c src/consensus.c  (phase enum, quorum formula)
     - src/pqc_crypto.c
     - src/pqc_crypto.c
     - src/pqc_crypto.c
   ========================================================================= *)

From Coq Require Import Arith.
From Coq Require Import Lia.
From Coq Require Import List.
From Coq Require Import Bool.
Import ListNotations.

(* -------------------------------------------------------------------------
   Protocol Phases (HotStuff 3-phase commit)
   Maps to: src/pqc_crypto.c CONSENSUS_PHASE_* enum
   ------------------------------------------------------------------------- *)
Inductive Phase : Type :=
  | Idle
  | Prepare
  | Precommit
  | Commit.

(* Decidable equality on Phase *)
Lemma phase_eq_dec : forall (p1 p2 : Phase), {p1 = p2} + {p1 <> p2}.
Proof. decide equality. Defined.

(* -------------------------------------------------------------------------
   UTXO Status
   Maps to: src/pqc_crypto.c  utxo->spent (bool)
   ------------------------------------------------------------------------- *)
Inductive UTXOStatus : Type :=
  | Unspent
  | Spent.

Lemma utxo_status_eq_dec : forall (s1 s2 : UTXOStatus), {s1 = s2} + {s1 <> s2}.
Proof. decide equality. Defined.

(* -------------------------------------------------------------------------
   2PC Coordinator State
   Maps to: src/pqc_crypto.c cross-shard state machine
   ------------------------------------------------------------------------- *)
Inductive CoordState : Type :=
  | CInit
  | Waiting
  | CCommitted
  | CAborted.

Lemma coord_state_eq_dec : forall (s1 s2 : CoordState), {s1 = s2} + {s1 <> s2}.
Proof. decide equality. Defined.

(* -------------------------------------------------------------------------
   2PC Participant State
   Maps to: src/pqc_crypto.c participant state in cross-shard protocol
   ------------------------------------------------------------------------- *)
Inductive PartState : Type :=
  | PInit
  | Prepared
  | PCommitted
  | PAborted.

Lemma part_state_eq_dec : forall (s1 s2 : PartState), {s1 = s2} + {s1 <> s2}.
Proof. decide equality. Defined.

(* -------------------------------------------------------------------------
   Quorum Definition — Strict Supermajority

   quorum(n) = 2*n/3 + 1, ensuring strictly more than 2/3 of validators.
   This is the foundation of BFT safety: any two quorums must overlap
   in at least one honest validator.

   Maps to: src/pqc_crypto.c consensus.c: bft_quorum() function
     - src/pqc_crypto.c
     - src/pqc_crypto.c
   ------------------------------------------------------------------------- *)
Definition quorum (n : nat) : nat := 2 * n / 3 + 1.

(* -------------------------------------------------------------------------
   BFT Assumption: N >= 3F + 1

   The system tolerates at most F Byzantine faults among N validators.
   This is encoded as a hypothesis in theorems that require it, not
   as a global axiom.
   ------------------------------------------------------------------------- *)
Definition bft_valid (n f : nat) : Prop := n >= 3 * f + 1.

(* -------------------------------------------------------------------------
   WAL Entry Types (for cross-shard 2PC model)
   Maps to: src/pqc_crypto.c WAL record types
   ------------------------------------------------------------------------- *)
Inductive WALEntryType : Type :=
  | WAL_Prepare
  | WAL_Committed
  | WAL_Aborted.

(* -------------------------------------------------------------------------
   Shared List Utilities

   Used by UTXOSafety.v and CrossShard.v for indexed state access.
   These abstract over C array indexing (utxo_set->entries[i]).
   ------------------------------------------------------------------------- *)

(* Read the n-th element of a list *)
Fixpoint nth_opt {A : Type} (l : list A) (n : nat) : option A :=
  match l, n with
  | [], _ => None
  | h :: _, O => Some h
  | _ :: t, S n' => nth_opt t n'
  end.

(* Update the n-th element of a list *)
Fixpoint update_nth {A : Type} (l : list A) (n : nat) (v : A) : list A :=
  match l, n with
  | [], _ => []
  | _ :: t, O => v :: t
  | h :: t, S n' => h :: update_nth t n' v
  end.
