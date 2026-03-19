# HIG-002: Cryptographic Downgrade Exposure (ED25519 Fallback + Unrestricted Algorithm Selection)

### 1. Classification
- Type: Cryptographic Misuse / Downgrade
- CWE: CWE-757 (Selection of Less-Secure Algorithm During Negotiation)
- Severity: High
- Exploitability: Conditional

---

### 2. Affected Component
- File(s):
  - `src/pqc_crypto.c`
  - `go/higgaion.go`
  - `rust/src/lib.rs`
  - `python/higgaion/core.py`
  - `tests/test_pqc_crypto.c`
  - `go/higgaion_test.go`
  - `rust/tests/integration_tests.rs`
  - `python/tests/test_crypto.py`
  - `enterprise_gateway_deployment_guide.md`
  - `enterprise_gateway_client_implementation_guide.md`
- Function(s): `generate_keypair` (C), `GenerateKeypair` (Go/Python), `generate_keypair` (Rust)
- Layer: C core + FFI + operational docs

---

### 3. Vulnerability Description
Invariant required under a PQ adversary: **security must not silently reduce from PQ signatures to classical signatures**.

Reality:
- The core API accepts an arbitrary `alg_name` string.
- The test suite and enterprise docs explicitly recommend/perform fallback to `ED25519` when ML-DSA-87 is unavailable.
- This creates a real deployment failure mode where the system is believed to be PQC-authenticated but actually operates classically.

This is a design + operational control flaw: policy is not enforced by the cryptographic boundary.

---

### 4. Root Cause Analysis
- No allowlist or “policy lock” at the cryptographic boundary.
- “Optional fallback” is normalized in tests/docs, increasing the chance it becomes production behavior.
- No transcript-binding/attestation that ML-DSA-87 is in use.

---

### 5. Attack Scenario
- Initial state: Gateway deployed on heterogeneous nodes; some lack ML-DSA providers.
- Attacker capabilities: can trigger availability/compatibility edges (routing to older nodes, exploiting partial rollouts/partitions).
- Step-by-step:
  1) Operator deploys expecting `ML-DSA-87`.
  2) A subset of nodes lacks ML-DSA support → system falls back to `ED25519` per documented “interim workaround.”
  3) Attacker targets those nodes and leverages classical compromise (key theft) or the assumed nation-state capabilities to defeat classical assurances.
- Resulting system violation: post-quantum security posture collapses to classical where downgrade is enabled.

---

### 6. Proof of Concept (PoC)
Code-level PoC (Go): the library accepts ED25519 and performs signing/verification successfully:

```go
priv, pub, _ := higgaion.GenerateKeypair("ED25519")
sig, _ := priv.Sign([]byte("msg"), "domain")
ok := pub.Verify([]byte("msg"), sig, "domain") // ok == true
```

The repo’s own tests and enterprise docs treat this downgrade as acceptable under provider-missing conditions.

---

### 7. Impact Analysis
- Confidentiality impact: indirect (authorization bypass enables data access).
- Integrity violation: direct (attacker can authorize operations with non-PQ guarantees).
- Authentication bypass: yes, under PQ threat model or classical key compromise.
- Replay / forgery / key compromise: enabled against downgraded nodes.

---

### 8. Formal Security Impact
- Invalidates: **quantum resistance claim** for the deployed system (security reduces to ED25519 where enabled).
- Breaks any protocol-level claim that requires PQ signatures for authentication.

---

### 9. Mitigation / Fix
- Code-level:
  - Remove `alg_name` from production-facing APIs; provide fixed ML-DSA-87 functions.
  - If algorithm agility is required, enforce an allowlist and refuse insecure algorithms by default.
- Operational:
  - Fail closed if ML-DSA-87 provider is missing (no fallback).
  - Emit an explicit attestation/metric that ML-DSA-87 is active; treat non-PQC as incident.
- Protocol-level:
  - Bind algorithm choice into signed transcript and configuration, preventing silent downgrade.

---

### 10. Verification Strategy
- Unit tests: ensure ED25519 is rejected in “PQC-required” builds/configs.
- Integration tests: simulate missing provider; verify startup fails (not downgrades).
- CI policy: require ML-DSA-87 availability on release targets; block “fallback” paths outside test builds.

