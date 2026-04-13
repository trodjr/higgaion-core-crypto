# Higgaion Peer Review Guide

Thanks for checking out the repo! This is a solo research project — 101 Gallina theorems in Coq (zero admitted lemmas), OpenSSL PQC wrappers, and the core of the zero-downtime migration engine (Patent Pending: U.S. Pat. App. 64/000,480).

## What reviewers should focus on
- `coq/PQCMigration.v` — especially the 4-state FSM invariants, `PQC_ONLY_irreversible`, disjunctive OR-mode safety, and adversarial crash recovery with Erasure-Before-WAL
- `pqc_crypto.c` — domain separation, `OPENSSL_cleanse` timing, error handling
- Whether the hybrid OR-mode logic should land in C sooner (it’s currently modeled mathematically in Coq but not fully integrated into the standalone wrapper)

## Academic Bounty (Attribution & Co-Authorship)
As an open-source, independent research project, we reward peer review with permanent academic and professional attribution rather than cash bounties.

First person to:
- **Find a valid Coq counter-example to any invariant** → Name permanently engraved in the Whitepaper Acknowledgements + Repository Hall of Fame.
- **Spot a memory-safety or timing issue in the C wrappers** → Priority issue attribution + Repository Hall of Fame.
- **Demonstrate a practical attack on the migration protocol architecture** → Full Co-Author credit on the upcoming ePrint vulnerability paper.

## Where to leave feedback
- Open an Issue here on GitHub
- ePrint.iacr.org (I’ll submit the whitepaper + repo link this week)
- Coq Zulip, r/crypto, or PQC Discord

We read everything. Let’s make this citation-worthy.

—T-Rod (trodjr / inquiries@higgaion.io)
