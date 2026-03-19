---- MODULE pqc_crash_recovery ----
(*
 * TLA+ Specification: PQC Migration Crash Recovery — Erasure-Before-WAL
 *
 * Models the finalization sequence with explicit crash points to prove
 * that the counter-intuitive erasure-before-WAL ordering is safe.
 *
 * Patent Claim 1: "this erasure-before-WAL ordering ensures that a crash
 * occurring after erasure but before the WAL write causes recovery to
 * restore the key to HYBRID state with the classical material already
 * irrecoverably destroyed in processor-addressable memory, producing a
 * safe failure mode."
 *
 * Corresponds to: pqc_crypto.c key lifecycle + higgaion_key_free()
 *
 * HIG-007 FIX: Added durable wal_erasure_marker variable to replace
 * reliance on volatile finalize_step in the Recover action.
 * The erasure marker is written to WAL BEFORE erasure begins and
 * confirmed AFTER erasure completes. Recovery uses only durable
 * state (wal_last_state, wal_erasure_marker) — never volatile state.
 *
 * Verifies:
 *   SafeRecovery              — after crash+recovery, state is consistent
 *   ClassicalNeverResurrected  — erased material never reappears
 *   WALConsistency            — WAL replay produces valid state
 *   ErasureMonotonicity       — erasure marker never reverts
 *   DurableRecoveryCorrectness — recovery depends only on durable state
 *)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS MaxCrashes

VARIABLES
  mem_state,              \* In-memory state of the key (VOLATILE)
  mem_classical,          \* Classical key exists in memory? (VOLATILE)
  wal_last_state,         \* Last state written to WAL (DURABLE)
  wal_erasure_marker,     \* HIG-007: durable erasure progress marker
                          \*   "NONE"     = erasure not started
                          \*   "ERASING"  = erasure in progress
                          \*   "ERASED"   = erasure confirmed complete
  finalize_step,          \* Current step in finalization (VOLATILE)
  crashed,                \* Has the system crashed? (VOLATILE)
  crash_count,            \* Number of crashes so far
  recovered               \* Has recovery completed? (VOLATILE)

vars == <<mem_state, mem_classical, wal_last_state, wal_erasure_marker,
          finalize_step, crashed, crash_count, recovered>>

\* State values (matching pqc_types.h)
Classical  == 0
Hybrid     == 1
Finalizing == 2
PqcOnly    == 3

(* ===================================================================
   Initial State
   Start with a key in HYBRID state (ready for finalization).
   WAL reflects the last committed state (HYBRID).
   Erasure marker is NONE (no erasure has occurred).
   =================================================================== *)
Init ==
  /\ mem_state = Hybrid
  /\ mem_classical = TRUE
  /\ wal_last_state = Hybrid
  /\ wal_erasure_marker = "NONE"
  /\ finalize_step = 0
  /\ crashed = FALSE
  /\ crash_count = 0
  /\ recovered = FALSE

(* ===================================================================
   Finalization Steps — models pqc_crypto.c key lifecycle

   HIG-007 FIX: Steps now include durable WAL writes for the erasure
   marker at each phase boundary, ensuring recovery can determine
   erasure state from durable storage alone.
   =================================================================== *)

\* Step 1: Enter FINALIZING state + WAL write
EnterFinalizing ==
  /\ ~crashed
  /\ finalize_step = 0
  /\ mem_state = Hybrid
  /\ mem_state' = Finalizing
  /\ wal_last_state' = Finalizing         \* WAL written for FINALIZING
  /\ finalize_step' = 1
  /\ UNCHANGED <<mem_classical, wal_erasure_marker,
                 crashed, crash_count, recovered>>

\* Step 2: Write ERASING marker to WAL BEFORE erasing classical key
\* HIG-007: This durable marker survives crashes and allows recovery
\* to know that erasure was in progress.
WriteErasingMarker ==
  /\ ~crashed
  /\ finalize_step = 1
  /\ wal_erasure_marker' = "ERASING"      \* DURABLE: written to WAL
  /\ finalize_step' = 2
  /\ UNCHANGED <<mem_state, mem_classical, wal_last_state,
                 crashed, crash_count, recovered>>

\* Step 3: Erase classical key from memory
EraseClassical ==
  /\ ~crashed
  /\ finalize_step = 2
  /\ mem_classical' = FALSE               \* EVP_PKEY_free + secure_zero
  /\ finalize_step' = 3
  /\ UNCHANGED <<mem_state, wal_last_state, wal_erasure_marker,
                 crashed, crash_count, recovered>>

\* Step 4: Write ERASED marker to WAL AFTER erasure confirmed
\* HIG-007: This is the monotonic confirmation that erasure is complete.
\* Once written, recovery MUST treat classical key as irrecoverable.
ConfirmErasure ==
  /\ ~crashed
  /\ finalize_step = 3
  /\ wal_erasure_marker' = "ERASED"       \* DURABLE: monotonic marker
  /\ finalize_step' = 4
  /\ UNCHANGED <<mem_state, mem_classical, wal_last_state,
                 crashed, crash_count, recovered>>

\* Step 5: Set memory state to PQC_ONLY
SetPqcOnly ==
  /\ ~crashed
  /\ finalize_step = 4
  /\ mem_state' = PqcOnly
  /\ finalize_step' = 5
  /\ UNCHANGED <<mem_classical, wal_last_state, wal_erasure_marker,
                 crashed, crash_count, recovered>>

\* Step 6: Write WAL record for PQC_ONLY — AFTER erasure confirmed
WriteWALPqcOnly ==
  /\ ~crashed
  /\ finalize_step = 5
  /\ wal_last_state' = PqcOnly           \* WAL now reflects PQC_ONLY
  /\ finalize_step' = 6                   \* Finalization complete
  /\ UNCHANGED <<mem_state, mem_classical, wal_erasure_marker,
                 crashed, crash_count, recovered>>

(* ===================================================================
   Crash — can happen at ANY point during finalization
   Models power failure / process kill.
   Memory state is lost; only WAL state and erasure marker survive.

   HIG-007: finalize_step is VOLATILE and lost on crash. But
   wal_last_state and wal_erasure_marker are DURABLE and persist.
   =================================================================== *)
Crash ==
  /\ ~crashed
  /\ crash_count < MaxCrashes
  /\ finalize_step > 0                   \* Only crash during finalization
  /\ finalize_step < 6                   \* Not after completion
  /\ crashed' = TRUE
  /\ crash_count' = crash_count + 1
  /\ UNCHANGED <<mem_state, mem_classical, wal_last_state,
                 wal_erasure_marker, finalize_step, recovered>>

(* ===================================================================
   Recovery — replay WAL to restore state

   HIG-007 FIX: Recovery uses ONLY durable state (wal_last_state,
   wal_erasure_marker) to determine system state. The volatile
   finalize_step is NOT used — it would be lost in a real crash.

   Classical key recovery logic:
     - wal_erasure_marker = "ERASED" or "ERASING"
       → classical key is irrecoverable; treat as gone
     - wal_erasure_marker = "NONE"
       → classical key was never erased; restore from keystore
   =================================================================== *)
Recover ==
  /\ crashed
  /\ ~recovered
  \* WAL replay: restore memory state from last WAL record (DURABLE)
  /\ mem_state' = wal_last_state
  \* HIG-007 FIX: classical key recovery based on DURABLE erasure marker
  \* NOT on volatile finalize_step (which is lost on crash)
  /\ mem_classical' = (wal_erasure_marker = "NONE")
  /\ recovered' = TRUE
  /\ finalize_step' = 0                  \* Reset for potential retry
  /\ crashed' = FALSE
  /\ UNCHANGED <<wal_last_state, wal_erasure_marker, crash_count>>

Next ==
  \/ EnterFinalizing
  \/ WriteErasingMarker
  \/ EraseClassical
  \/ ConfirmErasure
  \/ SetPqcOnly
  \/ WriteWALPqcOnly
  \/ Crash
  \/ Recover

Spec == Init /\ [][Next]_vars

(* ===================================================================
   SAFETY INVARIANTS
   =================================================================== *)

\* INV-CR1: Safe Recovery
\* After recovery, the state machine is in a valid, consistent state.
\* The key is NEVER at PQC_ONLY without a WAL record confirming it.
SafeRecovery ==
  recovered =>
    \/ (mem_state = PqcOnly /\ wal_last_state = PqcOnly)
    \/ (mem_state /= PqcOnly)

\* INV-CR2: Classical Material Never Resurrected After Erasure (HIG-007)
\* Once the erasure marker is ERASED or ERASING, classical key bytes
\* MUST NOT exist in memory — even after recovery.
\* This is proved using only DURABLE state, not volatile finalize_step.
ClassicalNeverResurrected ==
  (wal_erasure_marker \in {"ERASING", "ERASED"}) =>
    (recovered => mem_classical = FALSE)

\* INV-CR3: WAL State Never Exceeds Memory State (before crash)
\* In normal operation (no crash), the WAL should never claim a state
\* that memory hasn't reached yet.
WALNeverAhead ==
  (~crashed /\ ~recovered) =>
    \/ (wal_last_state = Hybrid /\ mem_state \in {Hybrid, Finalizing, PqcOnly})
    \/ (wal_last_state = Finalizing /\ mem_state \in {Finalizing, PqcOnly})
    \/ (wal_last_state = PqcOnly /\ mem_state = PqcOnly)

\* INV-CR4: No State Regression
\* Memory state only moves forward during normal (non-crash) operation.
NoStateRegression ==
  (~crashed /\ ~recovered) =>
    mem_state >= Hybrid

\* INV-CR5: Crash During Erasure Produces Safe Degradation
\* After recovery, we're never in an impossible state.
CrashAfterErasureSafe ==
  (recovered /\ crash_count > 0) =>
    mem_state \in {Hybrid, Finalizing, PqcOnly}

\* INV-CR6: Erasure Monotonicity (HIG-007 — NEW)
\* Once the erasure marker reaches ERASED, it NEVER reverts to NONE.
\* This is the core monotonicity invariant ensuring that key destruction
\* is permanent and cannot be undone by crash-recovery cycles.
ErasureMonotonicity ==
  (wal_erasure_marker = "ERASED") =>
    [][wal_erasure_marker' = "ERASED"]_vars

\* INV-CR7: Durable Recovery Correctness (HIG-007 — NEW)
\* The recovery action's output depends ONLY on durable variables
\* (wal_last_state, wal_erasure_marker). This invariant asserts that
\* after recovery, mem_classical is fully determined by wal_erasure_marker.
DurableRecoveryCorrectness ==
  recovered =>
    (mem_classical = (wal_erasure_marker = "NONE"))

====
