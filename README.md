# Merkle Envelope Tools

**Deterministic, fully offline SPV verification and forensic audit tools for Bitcoin SV.**

Package a transaction with its Merkle proof and block header, then verify inclusion and
proof-of-work with no node, no API, and no third party - and get back a reproducible record
of *exactly what was proved and what was not*. The single idea the whole project is built
around: a green check that cannot be independently reproduced is not verification, it is
trust. So every tool states the precise scope of its verdict and refuses to imply more.

The tools speak the ecosystem's standard proof formats (BUMP / BRC-74, BEEF and Atomic-BEEF /
BRC-62 and BRC-95), so proofs move both ways with any BRC-62/74-compatible wallet (for example
`@bsv/sdk`). Pure vanilla JavaScript, zero dependencies.

## Why it exists

Most "verified" badges in practice mean "a server I trusted said so." This project replaces
that with a check the user runs themselves, offline, against a checkpoint they can audit - and
that is honest about the difference between "this transaction is in a block with valid
proof-of-work" and the much stronger claims (most-work chain, unspent status) that SPV cannot
make. The verification semantics are written down as a normative specification, and a second,
separately-written verifier is built from that specification to test whether the rules are
precise enough to reproduce.

## Tools

| Tool | Network | Purpose |
|------|---------|---------|
| `generator.html` | Online | Create Merkle envelopes (single or chain mode); emits legacy proof + BUMP |
| `headers-generator.html` | Online | Download a checkpoint-anchored `headers.bin` |
| `signer.html` | Offline | Sign transactions from envelopes (air-gapped; keys never touch a networked device) |
| `verifier.html` | Offline | Quick pass/fail verification (proof / BUMP / BEEF + chain inclusion) |
| `explorer.html` | Offline | Forensic SPV proof analysis with a deterministic verification record |
| `chain.html` | Offline | Multi-hop lineage verification (also accepts a single envelope) |
| `tests.html` | Offline | In-browser test-vector page (BUMP / BEEF / chain-inclusion) |
| `tests-mainnet.html` | Offline | In-browser real-mainnet verification page |
| `verify_vectors.py` | Offline | Standalone Python vector checker (stdlib only) |

**Workflow:** `generator.html` (online) -> USB -> `signer.html` (offline) -> USB -> broadcast
(online). Verify or audit any envelope offline with `verifier.html`, `explorer.html`, or
`chain.html`. Load order in HTML: `crypto.js` -> `encoding.js` -> `headers.js` -> `bump.js`
-> `beef.js`.

## Envelope format

```json
{
  "txid": "abc123...",
  "vout": 0,
  "satoshis": 100000,
  "rawTx": "0100000001...",
  "blockHeader": "00000020...",
  "proof": [{ "hash": "...", "pos": "R" }, { "hash": "...", "pos": "L" }],
  "bump": "fe...."
}
```

`txid` and `blockHeader` are required. A proof is supplied as `bump` (BRC-74 hex, preferred),
`beef` / `atomicBeef` (BRC-62 / BRC-95 hex), or a legacy `proof` branch; the verifier tries
them in that order. `vout` and `satoshis` are advisory (display only). A single envelope
object may be pasted anywhere an array is accepted (including `chain.html`), and existing
envelopes verify unchanged.

BUMP/BEEF live in `lib/bump.js` and `lib/beef.js`. The generator converts each source proof to
a BUMP and self-verifies it against the header's Merkle root before attaching it - if it does
not reconstruct, it keeps the legacy proof and warns rather than emitting a bad BUMP.
`beef.js parse` validates the Atomic-BEEF subject per BRC-95 (the subject must be present, must
be the last transaction, and the container may hold only its ancestors) and fails closed
otherwise.

## How verification works

For a standalone envelope the verifier checks, in order:

1. `txid == SHA256d(rawTx)` (in `verifier.html` and `chain.html`; `explorer.html` deliberately
   skips this and claims TXID inclusion, not transaction-byte inclusion).
2. The Merkle root, folded up from the txid through the supplied proof, equals the block
   header's own Merkle-root field.
3. The header meets its own proof-of-work: `SHA256d(header) <= target(nBits)`, with the hash
   compared as a little-endian 256-bit integer and `target(nBits)` decoded from the compact
   "nBits" encoding.
4. If a `headers.bin` is loaded, the block's computed hash is a member of that
   checkpoint-anchored, proof-of-work-linked header chain.

The block hash used everywhere is the computed `SHA256d(blockHeader)`, never a self-declared
value. Consensus math (PoW, target, floor, chain membership) lives once in `headers.js` and is
shared by every tool, so the tools cannot drift apart.

**Top-level verdicts (six).** Every verification resolves to exactly one:

- `VERIFIED` - all required claims hold, including membership in the loaded chain.
- `VERIFIED-ISOLATION` - proof and PoW hold, but no chain is loaded, so inclusion is not
  claimed. A distinct verdict, never shown as a chain-verified pass.
- `FAILED` - evidence is present and cryptographically contradicts the claim (root mismatch,
  invalid PoW, `txid != SHA256d(rawTx)`, block not in the loaded chain, or a chain-load
  failure).
- `POLICY-REJECTED` - the evidence is well-formed and cryptographically valid but a local
  policy rejects it (a sub-floor header, or a non-checkpoint anchor).
- `MALFORMED` - the input could not be parsed into a well-defined subject (bad hex, trailing
  bytes, truncation, depth over 32, an Atomic-BEEF subject that is not last).
- `INDETERMINATE` - the verifier itself could not finish evaluating (an internal or dependency
  failure). It never renders as a statement about the evidence.

Beneath these, each individual claim carries a per-claim status of ESTABLISHED or
NOT-ESTABLISHED; NOT-ESTABLISHED is used for the permanent scope boundaries below and is never
a top-level verdict for well-formed input. Advisories (for example low confirmations) sit on a
separate axis and never change the verdict.

## Trust model

Read this before relying on a verdict.

**You trust:** that the embedded checkpoint is the real block; that the data source was honest
at generation time; and that your offline machine is not compromised.

**You verify cryptographically:** that the transaction is in the Merkle tree; that the block
meets its own PoW target; that `txid == SHA256d(rawTx)`; and, when a `headers.bin` is loaded,
that the block is in a checkpoint-anchored, PoW-linked header chain.

**Checkpoint (block 939,999 - the anchor of `headers.bin`):**
```
height: 939999
hash:   00000000000000000e7aea9b454b4acc945e6ae5883ca7254809e538bb54ef12
nBits:  0x18227b71
```
The checkpoint is a single-source trust anchor. Internal PoW validity does not prove
canonicality - on BSV, roughly one block of work is within a resourced attacker's reach.
Independently confirm both the hash and the `nBits` on multiple explorers (for example
whatsonchain, blocks 939999 and 940000) before trusting high-value transactions. `headers.js`
exposes `checkpointFloorStatus()` and logs a warning if the configured `nBits` would ever make
the floor looser than difficulty-1.

**Difficulty floor - a heuristic, not consensus.** Enforced per header on a standalone
envelope header and on every header of a loaded chain: `target <= checkpoint_target x 8`.
Because chain membership can report any admitted header as "verified," the floor must hold for
every header, not just the tip, so one expensive floor-difficulty header cannot be amortized
across many cheap forged intermediates. Forging inclusion therefore costs at least about one
floor-difficulty block of proof-of-work - a heuristic cost bound, not economic finality. A
loaded chain may only make the floor stricter (raise-only); a low-difficulty tip can never
lower it. Accepted trade-off: a legitimate chain that genuinely contains a header more than 8x
easier than the checkpoint (a real BSV hashrate crash) is rejected - the chain fails closed,
exactly like any chain-load failure. The verdict does not silently downgrade to isolation
(isolation means no chain was loaded), and never to a false "verified." Retarget-aware (DAA)
validation is out of scope.

**Chain-index trust boundary.** Chain membership can establish a `VERIFIED` verdict only from
an index produced by the checkpoint-anchored, predecessor-validated loader. The shipped
verifiers enforce this structurally: the header index is an internal variable assigned only
from the loader's output and cleared on any load failure, and no verifier accepts a
caller-supplied index. An arbitrary hash lookup is therefore never equivalent to anchored
chain membership.

**Chain-inclusion states (never collapsed):**
- verified - the block is in the loaded, checkpoint-anchored chain (green, "inclusion proven").
- not in chain - a chain is loaded but this block is absent; fails closed (red).
- isolation - no chain loaded; PoW proven in isolation, inclusion not claimed; a distinct amber
  verdict, never the green of a chain-verified pass.
- load failed - a supplied `headers.bin` failed to verify; fails closed, with no silent
  downgrade to isolation.

## Limitations and anti-claims

SPV inclusion is a narrow claim. This tool is deliberate about what it does not establish:

- **Most-work chain.** "Verified" means membership in a checkpoint-anchored linked chain, not
  that it is the most-work honest chain. Cumulative work is computed but not compared.
- **Non-spend / current UTXO status.** SPV proves a transaction was mined; it cannot prove an
  output is still unspent. Any "unspent" claim needs a source that indexes spends.
- **Pre-checkpoint transactions.** The chain runs forward from block 939,999. A transaction in
  a block before the checkpoint can never be chain-verified with this checkpoint; it is
  permanently isolation-only. A post-checkpoint transaction needs a contiguous `headers.bin`
  from 939,999 up to its block.
- **Also out of scope:** blockchain sync, multi-source discovery, protecting a compromised
  machine, constant-time guarantees, P2SH / multisig / testnet, and Bitcoin Script or
  value-conservation evaluation for unmined BEEF ancestors.

Two design invariants underpin the above:

- **A verdict is a pure function of every input it depends on, and is invalidated when any of
  them changes.** The envelope and the loaded header chain are both inputs. `explorer.html`
  locks a verdict for reproducibility; loading or changing the header chain invalidates that
  lock and recomputes, so a displayed verdict always matches the currently-loaded evidence.
  (This came from a real bug: a locked isolation verdict once persisted on screen while a
  different chain was shown beside it.)
- **Evidence identity is not verdict identity.** The Replay ID / Verification Hash is an
  evidence digest: it commits to every field a verdict path reads (`txid`, `rawTx`,
  `blockHeader`, `proof`, `bump`, `beef` / `atomicBeef`) plus the checkpoint identity, floor
  tolerance, and spec version, with absent distinguished from empty. It deliberately does not
  commit to which chain was loaded or to the inclusion outcome, so the same envelope evaluated
  against different chain states shares one Replay ID. Equal evidence digest means same inputs,
  never same verdict. A separate result/verdict digest is deferred; see the specification.

## Specification and conformance

The verification semantics are written up normatively in `VERIFICATION-SEMANTICS-SPEC.md`:
inputs and byte order; the cryptographic invariants (including nBits-to-target decoding and the
little-endian PoW comparison); structural and policy invariants; the top-level verdicts and
their precedence; the INDETERMINATE evaluation boundary; evidence-identity invariants; scope
boundaries; and the chain-loading and anchoring algorithm that turns a raw `headers.bin` into a
checkpoint-anchored index.

Two spec-derived verifiers live outside the shipped tools and exist only to test whether the
specification is precise enough to reimplement from:

- `headers-node/` - a from-the-spec verifier plus `conformance.js`, a differential harness that
  checks both the reference and the spec-derived implementation against the specification's
  frozen corpus.
- `headers-node-independent/` - a second, separately-written verifier (`verify.js` plus
  `selftest.js`) built from the specification text and public standards, including
  trust-boundary tests.

Latest results, reproduced from a clean checkout: the frozen-corpus verdicts agree across the
reference and both implementations; the BRC-74 published vector and a real-mainnet fixture
verify independently; the chain loader produces a byte-identical anchored index; and
cross-binding attacks and unanchored-index injection are refused. Run them from the repo root:
`node headers-node/conformance.js` and `FIX=. node headers-node-independent/selftest.js`.

## Testing

Everything runs offline with no dependencies to install. From a clean checkout, one command
runs the whole Node-side suite:

```
npm test
```

That executes, in order and each as its own process: the `lib/bump.js` and `lib/beef.js`
self-tests; `test/test-audit-fixes.js` (14 checks: checkpoint enforcement, raise-only floor,
parser strictness, the `verifyMined` contract); `test/test-adversarial.js` (46 checks: a
forged low-difficulty chain rejected via a real PoW grind, fingerprint canonicalization,
checkpoint sanity, snapshot round-trip, Atomic-BEEF subject validation, per-header floor
policy including end-to-end wiring that a sub-floor intermediate is unreachable via chain
membership, scope anti-claims, and UI-state checks); `test/validate.js` (independent
differential validator, below); the DOM-stub integration harnesses `test/test-generator.js`,
`test/test-integration.js`, and `test/test-chain.js`; and the two spec-derived conformance
implementations `headers-node/conformance.js` and `headers-node-independent/selftest.js`. A
non-zero exit or any reported failure fails the whole run. No `npm install`, no network, and
no environment variables are required.

- `test/validate.js` checks `lib/bump.js` / `lib/beef.js` against the BRC-74 published test
  vector (an external anchor) and against an independent in-file Merkle oracle (a second
  Merkle implementation in the same file - independent in logic, not in authorship) across 20
  tree shapes, plus BEEF round-trip and tamper coverage. Its per-run assertion total is
  intentionally not deterministic (unseeded randomness), so no fixed count is cited.
- `test/verify-real-envelope.js` verifies a real mainnet envelope end-to-end; run it directly
  (`node test/verify-real-envelope.js`).
- `tests.html` (82 vectors) and `tests-mainnet.html` (31 real-mainnet tests) are in-browser
  pages, not part of `npm test`. In this repository they are exercised via a Node DOM-stub
  harness; a real-browser run is straightforward but is the user's to confirm.

No external-SDK differential harness exists, and none of the above substitutes for independent
review (see License).

### Parser fuzzing

`test/fuzz.js` is a deterministic, seed-logged fuzzer for the byte-level parsing surface -
the one part of the system least exercised by curated vectors. It takes known-valid corpus
items (the BRC-74 BUMP vector, the real envelope, the real `headers.bin`) and applies
structured hostile mutations (truncation, varint/offset/count corruption, `nBits` exponent
and sign-bit boundaries, header-count/length mismatch, byte flips) across five surfaces:
BUMP, block-header/PoW, the `headers.bin` loader, a full envelope through the verifier, and
BEEF. Each mutated input is checked against four invariants - no unexpected exception (A), no
false acceptance without a holding txid->root->header binding (B), a typed outcome (C), and
determinism (D) - and, where the independent reimplementation covers the same surface, the
two are run differentially and any outcome-class disagreement is recorded, never hidden.

At **seed 20260101, 100,000** deterministic structured mutations across those five surfaces
produced **zero observed exceptions, false acceptances, typed-outcome violations, differential
divergences, or non-determinism.** This is a bounded, reproducible result for exactly the
mutations tested at that seed - not a claim that the parsers are free of defects. Reproduce it:

```
node test/fuzz.js --seed 20260101 --iters 100000     # the 100k run above
npm test                                             # runs a bounded 20,000-iteration check at the same seed
node test/fuzz.js --seed 20260101 --replay 4242      # re-run one iteration with its full record
```

The harness is self-checking: injecting a one-off error into the target math makes it report
divergences and fail, so a clean run reflects the checks actually firing, not a silent
no-op. `test/fuzz.js` is an observer - it imports the production parsers and the independent
verifier but changes neither.

## Reproducibility and file hashes

Every file is offline, dependency-free, and self-contained, so a verdict on one machine
reproduces on another. Confirm you are running the audited bytes:

```
shasum -a 256 lib/*.js *.html *.py
```

| File | SHA-256 |
|------|---------|
| lib/crypto.js | `b2a91262f01994555e5e713cccb9d607c29b48ac5725f9bbce10df084ead0ab2` |
| lib/encoding.js | `22ea32359c2fd34aa9e421d99a2386f200e861bc7a364709745476d4091f57c1` |
| lib/secp256k1.js | `fc2d03baff7e802a8aed8e49a59c6b044089f9f585e1a1c9fe281b73da0e3e2b` |
| lib/sighash.js | `297151d898312ac0287abac527902ab4dec22804bbe1b782d4785bbbe789892f` |
| lib/headers.js | `f83c83e9459eea6eade8f0a4680fa1a3d5d41637edf57602f632fb1edf431a9a` |
| lib/bump.js | `b7fa41901c13ae2bbd570f78c889932954d414fb7e42129e0e3a3e64cad814e8` |
| lib/beef.js | `7b85bcd2e75c723269a2038333f256d2e9e8aa87b00d2859a53ca1d8c624ae53` |
| lib/snapshot.js | `5c391e376a4f2b2183f9e726db1e207e319ca976fba9c0fd5c9aea5179bd5442` |
| lib/mainnet-vectors.js | `b202b86e12f8d340f2f862845182838581b0643e65b338d57ce8ee93e6ca0155` |
| generator.html | `291ea1066f61379db1c9e66039e69680463d789ce554b32b0f6886599b1c9714` |
| headers-generator.html | `44fa51df0cec8ebc6cb1d5a4e0927e95f9c03a3f1c7d01c9506174378b93a5e1` |
| signer.html | `c4a85cffc27bd3721959d357e4c0fc272756089b37beca0b7c47792497338933` |
| verifier.html | `98e6552c74aaec483485156795f090ede1b48ac68cf573776bcf3ed16c40c50d` |
| explorer.html | `93d8886c2d872b2a357afbe53889a30c6001bc6e7707a315899be30532945e51` |
| chain.html | `2f4b95ca84577eeb4085405f4a5cebe007042d602add8f66c4f93b139f2ade0e` |
| tests.html | `79f51d56b03eee76c3fd56d5a3a351854e1f243a00c9a5fdf47eed754a574e44` |
| tests-mainnet.html | `264b74b2c3a410a509e4bc524d080ee7098e83837b8953e10352bb20dd4592e8` |
| verify_vectors.py | `6c015ddc2510139d886cc954c8b30cdd6c951aa93bc0a73cfb33602577d99be9` |

## Changelog (highlights)

Full detail, with per-finding rationale and tests, is in `AUDIT-FIXES.md`.

**Specification completion and conformance (no shipped-file or behaviour change)**
- `VERIFICATION-SEMANTICS-SPEC.md` made self-sufficient for reimplementation: the cryptographic
  section now defines SHA256d, header byte layout, nBits-to-target decoding, and the
  little-endian PoW comparison; legacy-proof sibling byte order is pinned; missing / empty /
  malformed header resolves to MALFORMED and the header-timestamp policy is normative; and the
  chain-loading and anchoring algorithm is specified.
- Two spec-derived verifiers (`headers-node/`, `headers-node-independent/`) reproduce the frozen
  corpus, the BRC-74 vector, a real-mainnet fixture, and a byte-identical anchored chain index,
  with zero divergences from the reference.
- **Chain-index trust boundary made explicit.** Membership can establish a VERIFIED verdict only
  from a checkpoint-anchored, loader-produced index. The shipped verifiers already enforce this
  structurally; the parameterized reimplementation now enforces it explicitly and fails closed
  to VERIFIED-ISOLATION for any unanchored index.
- No shipped file changed in this work; the hash table above is unaffected.

**v2.4.0 - semantic outcome contract (labels only; no decision or crypto changes)**
- One shared outcome vocabulary across verifier / explorer / chain, replacing three ad-hoc
  encodings. Accept/reject decisions and all cryptographic computation are byte-identical.
- POLICY-REJECTED distinguishes a below-floor but otherwise valid header from a cryptographic
  failure; INDETERMINATE distinguishes a verifier or dependency evaluation failure from invalid
  evidence, via a realm-safe error boundary (keyed on the error name, not the JS subclass).
  Advisories moved to a separate axis that never changes the verdict.
- Fixed a security inversion: an undefined or broken difficulty dependency was being reported as
  a difficulty-floor POLICY-REJECTED; it now correctly reports INDETERMINATE.
- Evidence digest (Replay ID) - deliberate breaking change. The digest now commits to
  `rawTx` / `bump` / `beef` / `atomicBeef` plus checkpoint identity, tolerance, and spec version,
  with absent distinguished from empty, closing a bump-blind collision. Pre-v2.4.0 Replay IDs
  are not comparable to current ones.

**v2.3.0 - review remediation and hardening**
- Checkpoint corrected and enforced: real block 939,999 / `0x18227b71` (was a placeholder whose
  nBits made the floor toothless). `verifyHeaderChain` fails closed on anchor mismatch, and a
  warning fires if the floor is ever looser than difficulty-1.
- Difficulty floor: per-header enforcement, raise-only dynamic floor; forging inclusion costs at
  least about one floor-difficulty block.

## License

MIT. **Use at your own risk.** This software handles cryptographic keys and financial
transactions. **Not independently security-audited** - validation to date is internal
differential testing (`test/validate.js`), the BRC-74 published test vector, and an internal audit
that informed the v2.3.0 hardening. A targeted review that finds and fixes issues is not the
same as, and is not a substitute for, a full independent third-party audit. Commission one
before relying on this for high-value transactions.
