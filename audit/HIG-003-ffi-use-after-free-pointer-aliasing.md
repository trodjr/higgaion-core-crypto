# HIG-003: FFI Wrappers Are Not Memory-Safe (EVP_PKEY Pointer Aliasing → Use-After-Free / Double-Free)

### 1. Classification
- Type: Memory Safety / FFI Lifecycle Violation
- CWE: CWE-416 (Use After Free)
- Severity: High
- Exploitability: Practical

---

### 2. Affected Component
- File(s):
  - `go/higgaion.go`
  - `rust/src/lib.rs`
  - `python/higgaion/core.py`
- Function(s):
  - Go: `GenerateKeypair`, `(*PrivateKey).Free`, `(*PublicKey).Verify`
  - Rust: `generate_keypair`, `Drop for PrivateKey`, `PublicKey::verify`
  - Python: `GenerateKeypair`, `PrivateKey.__del__`, `PublicKey.verify`
- Layer: FFI

---

### 3. Vulnerability Description
Invariant required: **safe-language wrappers must not expose UB through safe APIs**.

Reality: wrappers set `pub.pkey = priv.pkey` (aliasing a single OpenSSL object) but only one side frees it.
- If the private key is freed/dropped/GC’d while the public key remains referenced, the public key becomes a dangling pointer and verify becomes a UAF.
- If both are ever freed, you get double-free.

---

### 4. Root Cause Analysis
- Incorrect ownership model over a reference-counted OpenSSL object.
- Missing `EVP_PKEY_up_ref` when creating the “public key” wrapper view.
- Reliance on GC finalization ordering in Python, and implicit lifetime coupling in Rust/Go without encoding it in types.

---

### 5. Attack Scenario
- Initial state: A service generates a keypair, signs once, then retains only a “public key” object for verification tasks.
- Attacker capabilities: can trigger verification calls repeatedly (remote input).
- Step-by-step:
  1) Service signs, then drops private key (or Python GC collects it).
  2) Attacker sends requests requiring verification.
  3) Verification uses freed OpenSSL pointer → crash or systematic verification failure.
- Resulting system violation: **remote DoS**; in worst case, memory corruption if heap shaping becomes viable.

---

### 6. Proof of Concept (PoC)
C-level PoC mirroring wrapper behavior (alias pointer then free one side):

```c
pub.pkey = priv.pkey;
higgaion_key_free(&priv);
pqc_verify(..., &pub); // UAF
```

Observable impact: verification after freeing the private key fails unpredictably (e.g., `EVP_DigestVerifyInit` can fail due to the dangling key type/provider state).

---

### 7. Impact Analysis
- Confidentiality impact: conditional (UAF can become memory disclosure if exploited).
- Integrity violation: verification correctness becomes undefined.
- Authentication bypass: conditional (UB can fail-open depending on manifestation).
- Availability: practical crash/failure under load.

---

### 8. Formal Security Impact
- Invalidates: “memory-safe FFI” claim; any reasoning about correctness that assumes sound wrappers.
- Undermines authentication correctness (you cannot assume fail-closed when UB is present).

---

### 9. Mitigation / Fix
- C core: expose a function to safely clone/up-ref keys, e.g. `higgaion_key_up_ref(dst, src)` calling `EVP_PKEY_up_ref`.
- Wrappers:
  - Go: up-ref when assigning `pub.inner.pkey`, add `(*PublicKey).Free`.
  - Rust: up-ref; implement `Drop for PublicKey`.
  - Python: up-ref; implement `PublicKey.__del__` with independent ownership.
- Encode lifetime coupling: if you insist on aliasing, make `PublicKey` borrow from `PrivateKey` (Rust) rather than owning.

---

### 10. Verification Strategy
- Add explicit tests:
  - Public key verify must remain correct after private key is freed/dropped.
  - Double-free must be impossible (or must be safe via refcounts).
- Run sanitizers on Linux (`ASAN/UBSAN`) plus fuzz verification after forced frees.
- Add Python stress tests for GC ordering (cyclic refs + forced collections).

