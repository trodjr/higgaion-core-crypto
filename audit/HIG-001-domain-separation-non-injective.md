# HIG-001: Domain Separation Is Non-Injective (Prefix Collision + Silent Truncation)

### 1. Classification
- Type: Cryptographic Misuse / Domain Separation Failure
- CWE: CWE-347 (Improper Verification of Cryptographic Signature)
- Severity: Critical
- Exploitability: Practical

---

### 2. Affected Component
- File(s):
  - `src/pqc_crypto.c`
  - `include/higgaion/pqc_crypto.h`
  - (Claimed behavior in) `enterprise_gateway_deployment_guide.md`, `enterprise_gateway_client_implementation_guide.md`
- Function(s): `pqc_sign`, `pqc_verify`
- Layer: C core

---

### 3. Vulnerability Description
Invariant claimed/required: **A signature bound to `(domain_separation_tag, message)` must not validate under any other `(domain', message')` unless both pairs are identical.**

Actual behavior: the implementation computes `buffer = domain || message` with `dom_len = strnlen(domain, 4096)` and signs/verifies `buffer`. This mapping is **not injective**:
- **Prefix collision**: `(d1, m1) ≠ (d2, m2)` can still produce the same concatenation (`d1||m1 = d2||m2`).
- **Silent truncation**: any domain longer than 4096 bytes is effectively truncated to its first 4096 bytes, collapsing distinct domains to the same signed prefix.

This is an implementation flaw with protocol-level consequences.

---

### 4. Root Cause Analysis
- Missing unambiguous encoding (no length prefix, no delimiter with a stated forbidden set, no structured hashing).
- Unsafe “safety” cap (`strnlen(..., 4096)`) that truncates rather than rejects overlong domains, creating equivalence classes of domains.

---

### 5. Attack Scenario
- Initial state: A signing service signs requests for multiple domains (e.g., staging vs production).
- Attacker capabilities: chosen-message queries in a low-impact domain; replay/manipulation of traffic.
- Step-by-step:
  1) Attacker requests a signature for domain `A` on message `BC`.
  2) Attacker submits the signature to a verifier for domain `AB` on message `C`.
  3) Verifier reconstructs `AB||C = ABC`, identical to the signed bytes, and accepts.
- Resulting system violation: **cross-domain authorization bypass** even though “domain separation” is present.

---

### 6. Proof of Concept (PoC)
Code-level PoC (C) demonstrating cross-domain validation via prefix collision (returns `TRUE` with current implementation):

```c
// Sign (domain="A", msg="BC"), verify (domain="AB", msg="C")
const char *domain1="A";  const uint8_t msg1[]="BC";
pqc_sign(&sig,&sig_len,msg1,2,domain1,&key);

const char *domain2="AB"; const uint8_t msg2[]="C";
bool ok = pqc_verify(msg2,1,sig,sig_len,domain2,&key); // ok == true
```

Also exploitable via truncation:
- `domain2 = "A"*4096 + "B"` signs/verifies as if the domain were `"A"*4096`.

---

### 7. Impact Analysis
- Confidentiality impact: indirect (cross-domain confusion can route signed actions to unintended trust zones).
- Integrity violation: **signature accepted for wrong domain** (authorization boundary breach).
- Authentication bypass: yes (domain is part of the authentication context per docs).
- Replay / forgery / key compromise: enables **cross-domain replay** by construction.
- Cross-domain contamination: direct.

---

### 8. Formal Security Impact
- Invalidates: **Domain Separation** property (the core claim in gateway docs).
- Does *not* break ML-DSA EUF-CMA as a primitive; it breaks the *scheme construction* used to bind domains.

---

### 9. Mitigation / Fix
Concrete code-level fix (minimum):
- Reject overlong domains rather than truncating:
  - If `strnlen(domain, MAX) == MAX`, return error (treat as invalid/untrusted).
- Make domain separation injective:
  - Use length-prefix encoding: `len(domain)||domain||len(msg)||msg`
  - Or sign a structured hash: `H = SHA3-256("HIG_DS_V1" || u32_be(len(domain)) || domain || u64_be(len(msg)) || msg)` and sign `H`.

Protocol-level fix:
- Specify domain tags as **byte strings with explicit length** and canonicalization rules.

---

### 10. Verification Strategy
- Unit tests: include the exact collision cases:
  - `("A","BC")` vs `("AB","C")` must fail.
  - `("A"*4096, msg)` vs `("A"*4096+"B", msg)` must fail.
- Property-based tests: generate `(d1,m1,d2,m2)` where encodings collide; verify rejection.
- Differential fuzzing: fuzz domain/message encoding and compare against a reference encoding implementation.

