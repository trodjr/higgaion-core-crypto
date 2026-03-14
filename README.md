# Higgaion Core Cryptography & Proofs

This repository contains the core post-quantum cryptographic primitives (ML-DSA and ML-KEM OpenSSL wrappers) and the **101 Gallina (Coq) Mechanized Proofs** that verify the safety invariants of the Higgaion PQC Migration Engine.

## Asciinema Demo: Zero-Downtime Migration
To see the full state machine, ML-DSA Disjunctive Verification, and the mathematically proven Erasure-Before-WAL crash recovery in action, play the included terminal recording:

![PQC Migration Zero-Downtime Demo](demo.gif)

## Quad-Tier Formal Verification
The proofs in `verification/coq/` compile with **zero admitted lemmas** under the Coq proof assistant. They demonstrate the mechanical correctness of our:
1.  **4-State Transition Matrix** (CLASSICAL → HYBRID → FINALIZING → PQC_ONLY)
2.  **Disjunctive (OR-Mode) Dual Signatures**
3.  **Adversarial Crash Recovery Invariants**

## Intellectual Property & Commercial Licensing
The cryptographic C implementations (`pqc_crypto.c`) and the formal Coq proofs (`verification/coq/`) within this repository are open-source and provided under the MIT License.

**PATENT NOTICE:** 
The overarching PQC crash-recoverable migration state machine, the Erasure-Before-WAL crash recovery architecture, and the Disjunctive (OR-Mode) Hybrid Verification protocols demonstrated in our engine are protected under **U.S. Patent Application No. 64/000,480**.

For commercial licensing of the full Crash-Recoverable Enterprise SDK (which manages the state transitions, WAL journaling, and Cloud KMS integration), please contact the lead cryptographic engineering team.
