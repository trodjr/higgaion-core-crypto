(* =========================================================================
   PQCMigrationExtract.v — Coq Extraction of PQC Migration Model to OCaml

   Extracts the verified Coq model to OCaml source code, enabling:
     1. Spec-implementation comparison against pqc_migration.c
     2. Executable reference implementation usable for test oracles
     3. Formally-verified migration logic that can be called from C via FFI

   The extracted OCaml code is mechanically generated from the proofs in
   PQCMigration.v, inheriting all verified properties:
     - State transition well-formedness
     - PQC_ONLY irreversibility
     - Key existence invariants
     - Generation monotonicity

   Run:
     cd verification/coq
     coqc -Q . Higgaion PQCMigrationExtract.v
     # Produces: pqc_migration_extracted.ml / pqc_migration_extracted.mli
   ========================================================================= *)

From Higgaion Require Import PQCMigration.
Require Extraction.
Require ExtrOcamlBasic.
Require ExtrOcamlNatInt.

(* -------------------------------------------------------------------------
   Extraction Configuration

   Map Coq types to efficient OCaml equivalents:
     nat → int (via ExtrOcamlNatInt)
     bool → bool (native)
     option → option (native)
   ------------------------------------------------------------------------- *)

(* Use OCaml native integers for nat (verified operations only) *)
Extract Inductive nat => "int" ["0" "succ"]
  "(fun fO fS n -> if n <= 0 then fO () else fS (n-1))".

(* Use OCaml native booleans *)
Extract Inductive bool => "bool" ["true" "false"].

(* Use OCaml native option *)
Extract Inductive option => "option" ["Some" "None"].

(* -------------------------------------------------------------------------
   Custom Type Mapping

   Map MigrationState to a readable OCaml variant type.
   ------------------------------------------------------------------------- *)
Extract Inductive MigrationState =>
  "migration_state"
  ["Classical" "Hybrid" "Finalizing" "PqcOnly"]
  "(fun fC fH fF fP s -> match s with
    | Classical -> fC ()
    | Hybrid -> fH ()
    | Finalizing -> fF ()
    | PqcOnly -> fP ())".

(* -------------------------------------------------------------------------
   Selective Extraction

   Extract only the computational content (types + functions).
   Proof terms are erased — only the verified API remains.
   ------------------------------------------------------------------------- *)
Extraction Language OCaml.
Set Extraction Output Directory "../../verification/coq/extracted".

(* Extract the full PQC migration model *)
Recursive Extraction
  MigrationState
  MigrationRecord
  well_formed
  import_key
  begin_migration
  enter_finalizing
  complete_finalization
  rollback.
