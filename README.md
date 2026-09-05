# Merkle Envelope Tools

Offline SPV verification and forensic audit tools for Bitcoin SV. No node. No network. No
trusted server.

Given a transaction, its Merkle proof, and block-header evidence, the tool determines exactly
what that evidence establishes - and keeps distinct claims distinct, so weaker evidence is
never silently promoted to stronger proof. Vanilla JavaScript, zero dependencies.

## What it proves

Each verification resolves these independently, then composes them into one typed verdict:

- **Transaction identity** - `txid == SHA256d(rawTx)`.
- **Merkle inclusion** - the proof folds to the block header's merkle root (BUMP / BEEF / legacy).
- **Proof-of-work** - `SHA256d(header) <= target(nBits)`.
- **Difficulty-floor policy** - the header's target is within a bounded multiple of the checkpoint's.
- **Chain membership** - the header is in a checkpoint-anchored, PoW-linked chain, when one is loaded.

A proof that holds with no chain loaded returns `VERIFIED-ISOLATION` (PoW and inclusion in a
block proven; on-chain membership not claimed), never the `VERIFIED` of a chain-confirmed
result. Malformed or insufficient evidence fails closed.

## Why it exists

"Verified" usually means "a server I trusted said so," and SPV tools routinely conflate distinct
claims - that a transaction exists, that it was mined, that it is on the most-work chain, that
its outputs are unspent. These do not follow from one proof. This tool keeps them separate and
labels the exact scope of every verdict. The rule it is built on: a green check you cannot
independently reproduce is not verification, it is trust.

## Quick start

Everything is offline and dependency-free. Open a tool in a browser:

- `verifier.html` - pass/fail verification (BUMP / BEEF / legacy proof + optional chain).
- `explorer.html` - forensic proof analysis with a deterministic verification record.
- `chain.html` - multi-hop lineage verification.
- `signer.html` - air-gapped P2PKH signing (see `ANTI-FEATURES.md`, `SIDE-CHANNELS.md`).
- `generator.html` / `headers-generator.html` - build envelopes / fetch a checkpoint-anchored `headers.bin` (online).

Run the test suite (Node >= 18; no install, no network):

```
npm test
```

## Verification model

PoW, target, difficulty-floor, and chain-membership verification lives once in `lib/headers.js`
and is shared by every tool; the block hash is always the computed `SHA256d(blockHeader)`, never
a self-declared value. The single trust anchor is the embedded checkpoint (block 939,999); a
loaded `headers.bin` must anchor to it or it fails closed, and is never silently downgraded to
isolation. Every file is self-contained, so a verdict reproduces across machines - confirm you
are running the reviewed bytes with `shasum -a 256 lib/*.js *.html`.

The complete normative semantics - byte order, `nBits` decoding, the outcome taxonomy and its
precedence, the evaluation boundary, evidence identity, and the `headers.bin` anchoring
algorithm - are in `VERIFICATION-SEMANTICS-SPEC.md`. Every bundled mainnet vector can be
reproduced independently against block explorers, direct computation, or a node; see
`CROSS-VERIFICATION.md`.

Scope note: `verifier.html` and `chain.html` bind `rawTx` (`txid == SHA256d(rawTx)`);
`explorer.html` deliberately does not, claiming TXID inclusion rather than transaction-byte
inclusion.

## What it does not prove

- **Most-work / canonical chain.** Membership in a checkpoint-anchored chain is not most-work-chain status; cumulative work is computed, not compared.
- **Unspent / current UTXO status.** SPV proves a transaction was mined, not that an output is still unspent.
- **Consensus validity.** No script execution or consensus-rule checking. This is not a consensus validator.
- **Pre-checkpoint transactions.** The chain runs forward from 939,999; earlier blocks are permanently isolation-only.

## Interoperability

Reads and writes BUMP (BRC-74) and BEEF / Atomic-BEEF (BRC-62 / BRC-95), so proofs move both
ways with any BRC-62/74-compatible wallet (for example `@bsv/sdk`).

## Security & testing

`npm test` runs deterministic unit, adversarial, and differential suites - including two
spec-derived verifiers that reimplement the semantics from the specification and reproduce the
reference with zero divergences, plus an independent Node-crypto Merkle oracle. Beyond that, the
byte-level parsers have been exercised by a deterministic, seed/replay **500,000-mutation
campaign** across BUMP, block headers / PoW, `headers.bin`, envelopes, and BEEF / Atomic-BEEF,
and the shipped `explorer.html`, `verifier.html`, and `chain.html` verification paths are fuzzed
with negative
controls that prove the harness can detect a planted false acceptance. The parser and
shipped-path fuzzers found and helped fix real production defects; findings and rationale are in
`AUDIT-FIXES.md`.

### Independent implementation agreement

BEEF semantics are independently reproduced by a from-scratch interpreter that shares no BEEF
parsing, transaction, encoding, or cryptographic implementation with the production verifier
(its only dependency is Node's SHA-256). Differential testing across deterministic hostile
inputs and valid multi-ancestor and Atomic-BEEF corpora found no structural or cryptographic
divergence: the two implementations agree on structure, transaction identity, ancestry, BRC-95
subject selection, and independently reconstructed Merkle roots. Bidirectional negative controls
demonstrate that the differential harness detects faults introduced independently into either
implementation. The same method underlies the two spec-derived header verifiers, which
reproduce the reference outcomes with zero divergences. A three-way conformance harness against
a third, external implementation (`@bsv/sdk`) is included; it runs when that SDK is installed in
a dev environment and otherwise reports that dimension as unavailable rather than approximating
it (this repository ships zero-dependency).

This is testing evidence, not a security proof: the project has not had an independent
third-party security audit, and the specification and both spec-derived verifiers share one
author. Confirm the checkpoint on multiple explorers, and commission an audit, before relying on
this for high-value transactions.

## License

MIT. Use at your own risk; this software handles cryptographic keys and financial transactions,
and is not independently security-audited.
