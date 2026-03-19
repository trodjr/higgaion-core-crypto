# HIG-006: Proof Integrity Failure (Vacuous Crypto Models + Spec/Implementation Divergence + Misstated Theorems)

### 1. Classification
- Type: Proof Gap / Assurance Failure
- CWE: N/A (formal-methods assurance defect)
- Severity: High
- Exploitability: Practical

---

### 2. Affected Component
- File(s):
  - `verification/coq/HiggaionTypes.v`
  - `verification/coq/PQCMigration.v`
  - `verification/coq/Gateway.v`
  - `verification/tla/pqc_crash_recovery.tla`
  - `verification/tla/pqc_distributed.tla`
  - `verification/framac/wp_pqc_wal.c`
  - `verification/cbmc/cbmc_pqc_migration_actual.c`
  - Documentation making verification claims: `README.md`, `REVIEW_GUIDE.md`, `linkedin_announcement.md`, `enterprise_gateway_deployment_guide.md`, `enterprise_gateway_client_implementation_guide.md`
- Function(s): multiple (formal models); “mapping” comments to absent functions/files
- Layer: Coq proofs / TLA specs / verification harnesses / docs

---

### 3. Vulnerability Description
Invariant required for formal assurance: **proved theorems must correspond to the implementation that is shipped and deployed**.

Findings:
- The compiled C core in this repo is essentially `src/pqc_crypto.c`, yet the formal artifacts repeatedly “map to” nonexistent sources (e.g., `src/pqc_migration.c`, `src/consensus.c`, `src/shard_wal.c`). There is no refinement link.
- “Cryptographic verification” is modeled as integer equality (`Nat.eqb`) in `verification/coq/PQCMigration.v`, which cannot justify any real cryptographic property.
- Example of claim/theorem mismatch:
  - “WAL Replay Idempotence” is proved as `wal_replay (wal_replay r log) [] = wal_replay r log`, which is not idempotence of replaying the WAL twice; it is a trivial empty-log property.

This is an assurance defect that causes high-risk overconfidence.

---

### 4. Root Cause Analysis
- No proof-to-implementation correspondence layer (no extraction used, no verified compilation, no trace refinement, no translation validation).
- Toy models substituted for cryptographic semantics.
- Documentation asserts stronger properties than the artifacts actually establish.

---

### 5. Attack Scenario
- Initial state: deployment decisions are made based on “formally verified” claims.
- Attacker capabilities: exploit real implementation flaws and operational misconfigurations.
- Step-by-step:
  1) Operators treat domain separation and hybrid verification as “mathematically assured.”
  2) Attacker exploits real implementation weaknesses (e.g., domain-collision bypass, downgrade paths, FFI UAF).
  3) Defender response is delayed because the assurance story is believed.
- Resulting system violation: security posture is weaker than believed; controls fail silently.

---

### 6. Proof of Concept (PoC)
Empirical contradiction to documented “mathematical rejection” of cross-domain replay:
- The C core accepts cross-domain verification via prefix collisions (see HIG-001 PoC), while enterprise docs assert this is impossible.

---

### 7. Impact Analysis
- Confidentiality/Integrity/Availability: downstream—depends on which false assurances were relied on.
- Operational impact: invalid compliance and audit narratives; brittle incident handling.

---

### 8. Formal Security Impact
- Invalidates any claimed end-to-end property for the deployed code (domain separation, crash recovery, migration irreversibility) absent a refinement proof.
- No basis for claiming EUF-CMA/IND-CCA2/composition security for the *system* based on these artifacts.

---

### 9. Mitigation / Fix
- Stop claiming implementation verification unless you ship the verified implementation and the correspondence proof.
- Provide one of:
  - Verified extraction used as the implementation (with tests comparing extracted vs C), or
  - A formal refinement proof tying the C implementation to the Coq/TLA spec, or
  - Verified compilation toolchain (CompCert/VST-style) for the relevant C code.
- Replace toy crypto models with explicit assumptions and prove the properties that matter (downgrade resistance, domain separation injectivity, replay resistance at the protocol layer).

---

### 10. Verification Strategy
- Add a “proof-to-code” gate in CI:
  - fail if “maps to” file paths do not exist in the repo
  - run trace refinement tests comparing C executions to extracted reference
- Run CBMC/Frama-C on the *actual* sources, not stubs/copies.
- Add adversarial models to TLA/Coq that include message injection/replay/stripping and prove invariants against them.

