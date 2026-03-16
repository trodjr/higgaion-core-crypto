# Higgaion Core Cryptography & Proofs

[![Build Status](https://github.com/trodjr/higgaion-core-crypto/actions/workflows/coq-build.yml/badge.svg)](https://github.com/trodjr/higgaion-core-crypto/actions/workflows/coq-build.yml)
[![codecov](https://codecov.io/gh/trodjr/higgaion-core-crypto/graph/badge.svg)](https://codecov.io/gh/trodjr/higgaion-core-crypto)

This repository contains the core post-quantum cryptographic primitives (ML-DSA OpenSSL wrappers) and the **101 Gallina (Coq) Mechanized Proofs** that verify the safety invariants of the Higgaion PQC Migration Engine.

🌐 **Official Website:** [higgaion.io](https://higgaion.io)

## Asciinema Demo: Zero-Downtime Migration
![PQC Migration Zero-Downtime Demo](demo.gif)

## Disjunctive Verification & Erasure-Before-WAL Whitepaper
We have published a comprehensive architectural whitepaper detailing the Disjunctive (OR-Mode) Hybrid Verification protocols and the inverted "Erasure-Before-WAL" journaling sequence. 

📄 **[Read the Academic Whitepaper (PDF)](higgaion_ACADEMIC_WHITEPAPER.pdf)**

The whitepaper explains:
1. Why standard database WALs fail during classical key destruction (SNDL vulnerability).
2. How to achieve uncoordinated, rolling zero-downtime upgrades across sharded, multi-node infrastructure.
3. The methodology behind the adversarial quad-tier formal verification pipeline.

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

make          # builds C + runs Coq proofs
make test     # (coming in next commit — 26 roundtrip tests)
make clean
```

## AI Methodology Disclosure (Radical Transparency)
This project embraces *radical transparency* regarding its development methodology. The C implementations, cryptographic state machine, and specifically the 101 Gallina formal proofs were engineered using state-of-the-art AI pair-programming models under the strict architectural guidance of a human protocol expert. 

We don't ask you to trust the AI's output, nor do we ask you to trust human ego. We ask you to trust the Coq compiler's AST evaluator. If there is a single hallucination, memory leak, or unproven lemma, the 101 proofs fail to compile. Mathematical truth supersedes all origins.

## Intellectual Property & Commercial Licensing
The cryptographic C implementations (`pqc_crypto.c`) and the formal Coq proofs (`verification/coq/`) within this repository are open-source and provided under the MIT License.

**PATENT NOTICE:** 
The overarching PQC crash-recoverable migration state machine, the Erasure-Before-WAL crash recovery architecture, and the Disjunctive (OR-Mode) Hybrid Verification protocols demonstrated in our engine are protected under **U.S. Patent Application No. 64/000,480**.

For commercial licensing of the full Crash-Recoverable Enterprise SDK (which manages the state transitions, WAL journaling, and Cloud KMS integration), please contact inquiries@higgaion.io
