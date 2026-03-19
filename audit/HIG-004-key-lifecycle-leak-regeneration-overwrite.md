# HIG-004: Key Lifecycle Leak in C Core (Regeneration Overwrites Pointer Without Freeing) + Key Material Persistence

### 1. Classification
- Type: Resource Management / Sensitive Data Lifetime
- CWE: CWE-401 (Memory Leak), CWE-226 (Sensitive Information Uncleared Before Release)
- Severity: High
- Exploitability: Conditional

---

### 2. Affected Component
- File(s): `src/pqc_crypto.c`
- Function(s): `generate_keypair`
- Layer: C core

---

### 3. Vulnerability Description
Invariant required: **regenerating a key must not leak prior key objects; key material lifetime must be bounded**.

Actual: `generate_keypair` sets `key->pkey = NULL` before generating a new key, without freeing an existing `EVP_PKEY*`. If `key->pkey` was previously non-NULL, the old pointer is lost and the old key object is leaked.

Consequences:
- unbounded memory growth under repeated rotations
- old private key material remaining resident longer than intended

---

### 4. Root Cause Analysis
- Missing precondition enforcement (`key->pkey` must be NULL) or missing safe replacement (`EVP_PKEY_free` old before overwrite).
- No explicit secure-memory strategy; relying on allocator/free behavior is not a valid key destruction claim.

---

### 5. Attack Scenario
- Initial state: service rotates keys periodically or on-demand.
- Attacker capabilities: can trigger key regeneration (API calls, forced re-init loops, induced failure modes).
- Step-by-step:
  1) Attacker triggers repeated regeneration.
  2) Each call leaks an `EVP_PKEY` and associated allocations.
  3) Process hits memory limits → crash.
- Resulting system violation: DoS; expanded window for secret extraction if any memory disclosure occurs later.

---

### 6. Proof of Concept (PoC)
Pointer-loss PoC:

```c
void *first = key.pkey;
generate_keypair(&key, "ML-DSA-87");
void *second = key.pkey; // first != second => first key leaked
```

---

### 7. Impact Analysis
- Confidentiality impact: increases blast radius of memory disclosure.
- Integrity violation: indirect.
- Availability: practical under repeated regen (memory exhaustion).

---

### 8. Formal Security Impact
- Breaks operational key lifecycle assumptions required for many security arguments (bounded exposure, timely destruction).
- Does not directly falsify EUF-CMA of ML-DSA, but makes system-level “key destruction” claims non-credible.

---

### 9. Mitigation / Fix
- Code-level:
  - If `key->pkey != NULL`, call `EVP_PKEY_free(key->pkey)` before overwrite.
  - Alternatively, reject regeneration unless `key->pkey == NULL` and return an error code.
- API-level:
  - Return `HigError` from `generate_keypair` and require callers to handle failure explicitly.

---

### 10. Verification Strategy
- Add tests that regenerate keys repeatedly and confirm no leak (valgrind/leak sanitizer on Linux).
- Add CBMC harnesses over the actual C code for “no lost pointer” invariants.
- Allocation-failure injection testing (platform-appropriate).

