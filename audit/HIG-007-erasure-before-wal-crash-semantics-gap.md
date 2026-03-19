# HIG-007: Erasure-Before-WAL Is Not Formally Grounded in a Durable Recovery Model (State Oracle + Resurrection Risk)

### 1. Classification
- Type: State Machine Violation / Crash-Recovery Semantics Gap
- CWE: CWE-841 (Improper Enforcement of Behavioral Workflow)
- Severity: High
- Exploitability: Conditional

---

### 2. Affected Component
- File(s):
  - `verification/tla/pqc_crash_recovery.tla`
  - `verification/coq/PQCMigration.v` (WAL model)
  - `verification/framac/wp_pqc_wal.c` (asserts safety by construction)
- Function(s): TLA `Recover` (and crash steps), Coq `apply_wal_record`/`wal_replay`
- Layer: Protocol logic / formal model

---

### 3. Vulnerability Description
Invariant required: **after crash+recovery, the system must not (a) falsely believe classical key material is destroyed when it can be resurrected from durable storage, nor (b) falsely rely on classical material that was erased.**

The TLA model uses `finalize_step` after a crash to decide whether erasure occurred, even though `finalize_step` is an in-memory progress variable that would not survive a crash. This is an implicit oracle. The Coq/Frama-C models similarly do not represent durable secret storage in a way that constrains “resurrection” vs “irrecoverable loss.”

---

### 4. Root Cause Analysis
- Crash model does not faithfully model which state survives power loss (volatile vs durable).
- No durable, monotonic marker for “classical secret erased” vs “classical secret still recoverable from keystore/WAL/backup.”
- Safety is asserted by model structure rather than derived from realistic persistence semantics.

---

### 5. Attack Scenario
- Initial state: system finalizing a key; classical secret is erased in RAM; WAL still says FINALIZING.
- Attacker capabilities: can induce crashes (power kill, SIGKILL, OOM) and exploit partitions/replay.
- Step-by-step:
  1) Crash occurs after erasure but before WAL commit to PQC_ONLY.
  2) Recovery replays WAL to FINALIZING but cannot *durably* know whether classical private key is gone.
  3) System either:
     - attempts rollback / legacy signing and fails (availability failure), or
     - reloads classical secret from a durable keystore/backup to proceed (security regression).
- Resulting system violation: either **irrecoverable outage** or **violation of key-destruction guarantees**.

---

### 6. Proof of Concept (PoC)
Protocol-level trace (crash injection) is sufficient; the current specs do not rule it out because they do not model the durable secret store and rely on volatile progress state.

---

### 7. Impact Analysis
- Confidentiality impact: risk of reintroducing classical secrets post-“erasure.”
- Integrity violation: migration state can lie about destruction/compliance.
- Availability: repeated crash window can brick keys or force permanent degraded mode.

---

### 8. Formal Security Impact
- Invalidates: claimed “classical key destruction” and “safe degradation” unless a durable recovery marker is formally enforced.
- Undermines audit/compliance statements derived from “irreversible finalization.”

---

### 9. Mitigation / Fix
- Make erasure state **durable and monotonic**:
  - WAL record `ERASING_CLASSICAL` before erasure; WAL record `CLASSICAL_ERASED` after erasure; only then `PQC_ONLY`.
  - Recovery logic must treat `CLASSICAL_ERASED` as irreversible and never reload classical private material.
- Explicitly model the keystore and what bytes persist; ensure no path exists that restores classical private bytes after erasure.

---

### 10. Verification Strategy
- Update TLA to eliminate reliance on volatile variables post-crash; explicitly model durable keystore contents.
- Model-check crash at every step with an adversary that can crash repeatedly.
- Add integration fault-injection tests (fsync discipline + `SIGKILL` at step boundaries) once an implementation exists.

