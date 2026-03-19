# SYSTEMIC RISK ASSESSMENT

## SAFE under adversarial deployment?
No.

## Primary failure mode (design vs implementation vs assumptions)
- Implementation failures: domain separation is bypassable (collision + truncation), C key lifecycle leaks, and FFI wrappers expose use-after-free via pointer aliasing.
- Design failures: OR-mode hybrid verification collapses security to the weakest component and enables signature stripping/downgrade acceptance.
- Assumption/assurance failures: the formal artifacts are not tied to the shipped implementation and include vacuous models/misstated theorems; they do not substantiate “mathematically verified” deployment claims.

## Most dangerous hidden failure mode
False assurance: “formal verification” branding and “mathematical” language encourages high-threat deployments while critical authorization boundaries (domain separation and hybrid verification policy) are bypassable or degradable in practice.

## Framework Coverage (NIST + IEEE)
- Cryptographic Soundness: issues found (HIG-001, HIG-002, HIG-005)
- Implementation Safety: issues found (HIG-003, HIG-004)
- Protocol Invariants & State Machines: issues found (HIG-005, HIG-007)
- Attack Surface Modeling (STRIDE): issues found (HIG-001, HIG-002, HIG-003, HIG-005)
- Proof Integrity: issues found (HIG-006)
- Composition Risks: issues found (HIG-001, HIG-005)
- Operational Security: issues found (HIG-002, HIG-004, HIG-007)

Side-channels (timing/cache): No exploitable issue found under adversarial analysis assumptions in the audited C wrapper logic beyond variable-time operations on non-secret inputs; OpenSSL/provider constant-time behavior is not established by these artifacts and would require dedicated microarchitectural testing.

