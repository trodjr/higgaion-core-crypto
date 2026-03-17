# Higgaion Core Cryptography & Proofs

[![Build Status](https://github.com/trodjr/higgaion-core-crypto/actions/workflows/coq-build.yml/badge.svg)](https://github.com/trodjr/higgaion-core-crypto/actions/workflows/coq-build.yml)
[![codecov](https://codecov.io/gh/trodjr/higgaion-core-crypto/graph/badge.svg)](https://codecov.io/gh/trodjr/higgaion-core-crypto)

[![Coq](https://img.shields.io/badge/Language-Coq-blue.svg)](https://coq.inria.fr)
[![Lemmas](https://img.shields.io/badge/Admitted_Lemmas-0-success.svg)](#quad-tier-formal-verification)
[![Go Reference](https://pkg.go.dev/badge/github.com/trodjr/higgaion-core-crypto/go.svg)](https://pkg.go.dev/github.com/trodjr/higgaion-core-crypto/go)

This repository contains the core post-quantum cryptographic primitives (ML-DSA OpenSSL wrappers) and the **101 Gallina (Coq) Mechanized Proofs** that verify the safety invariants of the Higgaion PQC Migration Engine.

🌐 **Official Website:** [higgaion.io](https://higgaion.io)

## Asciinema Demo: Zero-Downtime Migration
![PQC Migration Zero-Downtime Demo](demo.gif)

## Disjunctive Verification & Erasure-Before-WAL Whitepaper
We have published a comprehensive architectural whitepaper detailing the Disjunctive (OR-Mode) Hybrid Verification protocols and the inverted "Erasure-Before-WAL" journaling sequence. 

📄 **[Read the Academic Whitepaper (PDF)](higgaion_ACADEMIC_PAPER.pdf)**

The whitepaper explains:
1. Why standard database WALs fail during classical key destruction (SNDL vulnerability).
2. How to achieve uncoordinated, rolling zero-downtime upgrades across sharded, multi-node infrastructure.
3. The methodology behind the adversarial quad-tier formal verification pipeline.

## Enterprise Gateway (Zero-Trust Edge Proxy)
Alongside the core engine, this repository also hosts the formal assurances for the **Enterprise Gateway**—a high-assurance sidecar proxy designed to bridge existing Identity Providers (IdP) to air-gapped Hardware Security Modules without exposing internal infrastructure.

### Proxy Behavior Under Adversarial Load
The proxy enforces rigorous domain-separation tags on incoming signatures.
- **Valid PQC Authorization**: The Gateway successfully proxies the request to the offline wallet.
![Gateway Success](assets/sidecar_success.gif)

- **Invalid or Downgrade Attack**: The Gateway actively rejects classical downgrades or mis-tagged signatures at the edge.
![Gateway Failure](assets/sidecar_failure.gif)

The Gateway state machine operates under its own formally verified invariants located in:
- `coq/Gateway.v` (Mechanized Gallina Proofs)
- `tla/Gateway.tla` (Temporal Logic of Actions specifications)

## Quad-Tier Formal Verification
The proofs in `coq/` compile with **zero admitted lemmas**. They mechanically verify:
- 4-State Transition Matrix (CLASSICAL → HYBRID → FINALIZING → PQC_ONLY)
- Disjunctive (OR-Mode) Dual Signatures
- Adversarial Crash Recovery + Erasure-Before-WAL invariants

## Quick Start & Build
```bash
# Clone + build everything
git clone https://github.com/trodjr/higgaion-core-crypto.git
cd higgaion-core-crypto

make          # builds C core + runs Coq proofs
make test     # runs the 26 cryptographic roundtrip tests
make coverage # runs coverage suite (requires lcov/gcov)
make clean
```

## Language Bindings (Golang)

Higgaion Core Crypto provides a mathematically safe, idiomatic Go wrapper around the core C primitives using `cgo`. 

```go
import "github.com/trodjr/higgaion-core-crypto/go"

// Generate memory-safe ML-DSA-87 PQC keys
priv, pub, err := higgaion.GenerateKeypair("ML-DSA-87")
if err != nil {
	panic(err)
}
defer priv.Free() // Prevents OpenSSL pointer leaks

// Sign over a network domain boundary
sig, err := priv.Sign(message, "gateway-production-zone")

// Validate signature cryptographically
valid := pub.Verify(message, sig, "gateway-production-zone")
```

Execute the wrapper tests via the CLI:
```bash
make test-go
```

## AI Methodology Disclosure (Radical Transparency)
This project embraces *radical transparency* regarding its development methodology. The C implementations, cryptographic state machine, and specifically the 101 Gallina formal proofs were engineered using state-of-the-art AI pair-programming models under the strict architectural guidance of a human protocol expert. 

We don't ask you to trust the AI's output, nor do we ask you to trust human ego. We ask you to trust the Coq compiler's AST evaluator. If there is a single hallucination, memory leak, or unproven lemma, the 101 proofs fail to compile. Mathematical truth supersedes all origins.

## Licensing

- **Code & Coq proofs** (, , etc.): Proprietary License (see [LICENSE](LICENSE))
- **Academic Whitepaper** (`higgaion_ACADEMIC_PAPER.pdf`): Creative Commons Attribution 4.0 (CC BY 4.0) — see footer on page 1
- **Patent-protected core**: U.S. Provisional Patent Application No. 64/000,480 (state machine, Erasure-Before-WAL, disjunctive protocol). Full enterprise SDK available via commercial license — contact inquiries@higgaion.io
