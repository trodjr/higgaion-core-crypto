# HIG-005: OR-Mode Hybrid Verification (As Specified) Is a Downgrade Oracle (Signature Stripping + Weakest-Link Security)

### 1. Classification
- Type: Protocol Design Flaw / Composition Risk
- CWE: CWE-757 (Selection of Less-Secure Algorithm During Negotiation)
- Severity: Critical
- Exploitability: Conditional

---

### 2. Affected Component
- File(s): `verification/coq/PQCMigration.v`
- Function(s): `hybrid_verify_disjunctive`, `hybrid_verify_pqc_preferred`
- Layer: Protocol logic / Coq proofs

---

### 3. Vulnerability Description
Invariant required under a PQ adversary: **once PQC is available/required, acceptance must imply PQC verification** (or an explicit, attacker-uncontrollable compatibility mode).

The OR-mode definition accepts if *either* classical or PQC signature verifies. That means:
- An attacker can strip the PQC signature component in transit and still be accepted if classical verifies.
- The effective security is at best the minimum of the component schemes (and under PQ threat, classical is the weak link).

The Coq file proves OR-mode permissiveness; it does not prove downgrade resistance or any cryptographic property.

---

### 4. Root Cause Analysis
- Design prioritizes “zero downtime” by permitting legacy acceptance without binding acceptance policy to a threat model boundary.
- Missing invariants for downgrade/stripping resistance (e.g., “if PQC key exists, PQC signature must be present and valid”).
- No transcript binding that makes “missing PQC component” unambiguously invalid.

---

### 5. Attack Scenario
- Initial state: system in HYBRID; verifiers accept OR-mode.
- Attacker capabilities: on-path manipulation; can delete or alter fields (PQC sig).
- Step-by-step:
  1) Client sends (classical_sig, pqc_sig).
  2) Attacker removes pqc_sig.
  3) Verifier accepts on classical_sig alone.
  4) If attacker can forge classical signatures (quantum assumption or key compromise), attacker authenticates without PQC.
- Resulting system violation: authentication bypass relative to PQ security goals.

---

### 6. Proof of Concept (PoC)
Formal counterexample (directly from the model witness used to prove permissiveness):
- `msg=0, csig=0, psig=1`
- `classical_verify msg csig = true`
- `pqc_verify_sig msg psig = false`
- `hybrid_verify_disjunctive = true`

This shows OR-mode acceptance does **not** imply PQC validity.

---

### 7. Impact Analysis
- Confidentiality impact: full compromise if authorization gates rely on hybrid verification.
- Integrity violation: forged actions accepted.
- Authentication bypass: yes, under the stated threat model.

---

### 8. Formal Security Impact
- Invalidates any claim of post-quantum authentication for the composed protocol while OR-mode is permitted.
- Composition fails: the protocol’s EUF-CMA reduces to the weakest component; downgrade resistance not achieved.

---

### 9. Mitigation / Fix
- Protocol redesign:
  - Use AND-mode composite signatures for security-critical operations.
  - If backward compatibility is required, make it **explicit and bounded** (separate endpoints / explicit opt-in / time-bound window).
  - If “PQC-preferred” is used, do **not** allow attacker-controlled absence to trigger fallback when PQC is configured/required.
- Implementation requirement (when code exists): require that HYBRID state messages include PQC signature and validate it; reject classical-only unless in explicit legacy mode.

---

### 10. Verification Strategy
- Extend Coq/TLA model with an adversarial channel that can strip fields.
- Prove a downgrade-resistance theorem: acceptance implies PQC validity once PQC key exists (outside explicit legacy).
- Add test vectors where pqc_sig is missing/empty; must fail under PQ-required policy.

