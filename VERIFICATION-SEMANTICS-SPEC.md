# Merkle Envelope Tools — Verification Semantics (specification precursor)

Status: **proposed**. This document specifies the *target* semantics for an independent
implementation (`headers-node`) and a conformance corpus. Where it describes what the code
does **today**, it says so explicitly and cites the location. Nothing here changes
production verification logic; the only code/doc changes made alongside it are the
authorised factual corrections listed in §M.

**Revision note (specification hygiene pass, reviewed against
`f4f3d3b306e671206bcb28c1cc399b9ace56d7f9`).** The readiness sections of this document had
fallen behind the code: they described the outcome enum, `POLICY-REJECTED`, `INDETERMINATE`,
the advisory axis and the evidence digest as *proposed*, when all five are implemented. Those
sections (§L, "Final independence test", "Conformance readiness", "Final question", and the
`@bsv/sdk` paragraph in §M) have been reconciled against the tree, with line cites. The
normative content — §§A–K and the frozen CONFORMANCE CONTRACT — is **unchanged** except for two
additions that document behaviour the ladder did not previously mention (the `NOT-ESTABLISHED`
fallthrough in §F/§G, and the digest framing as implemented in §K). No conformance claim was
strengthened: residuals R1–R4 are stated in the readiness section, including that no
independent third-party audit exists and that the specification and the spec-derived verifiers
share an author. **This pass changed no code.**

Guiding rules for this document:
- If a number does not reproduce, it is not cited as a fixed metric.
- If an external oracle does not exist, it is not claimed.
- If the verifier cannot know something, the model does not let it say it knows.
- Two semantically different outcomes never share one field.

---

## A. Scope

The verifier establishes, from a self-contained envelope plus an optional header chain,
that **a transaction is committed to a block whose header meets its own proof-of-work**,
and — when a checkpoint-anchored header chain is supplied — that **that block's header is a
member of that chain**. It is an offline SPV *inclusion* verifier, not a node.

It does **not** establish most-work-chain membership, current spend/UTXO status, script
validity, or value conservation (see §J).

## B. Evidence model

A verification subject is an envelope with these fields (`vout`, `blockHeader`+one proof
form are required; the rest optional):

`txid`, `vout`, `satoshis`, `rawTx`, `blockHeader`, `proof` (legacy single branch),
`bump` (BRC-74), `beef`/`atomicBeef` (BRC-62/95), plus self-declared `blockHash` /
`blockHeight` / `confirmations`. Optional external evidence: a `headers.bin` chain anchored
at the checkpoint. Policy inputs: the embedded checkpoint (`height`,`hash`,`nBits`) and the
difficulty-floor tolerance multiplier (×8).

Proof-selection order in the verifier (verifier.html:208–214): `bump` → `beef`/`atomicBeef`
→ legacy `proof`. **`bump` is preferred over `proof` when both are present.** This fact is
load-bearing for §K.

**Byte-order convention (clarified via the conformance experiment — this was previously
underspecified and caused an independent implementation to diverge).** `txid`, self-declared
`blockHash`, and the header's merkle-root *field* are DISPLAY (big-endian) order. The legacy
`proof[].hash` sibling values are **NATURAL (internal) byte order** and are used verbatim in
the fold (the txid is reversed to natural first; siblings are not reversed). `pos` (`'L'` /
`'R'`) denotes the **sibling's** side. BUMP (BRC-74) and BEEF (BRC-62) carry their own byte
order per those standards, so they are unaffected. An implementer who assumes legacy proof
hashes are display order will reject valid legacy proofs (a false negative); the reference and
the real mainnet fixture both use natural order.

**Required fields and header-state (GAP A resolution — this was previously contradictory:
§B said "required" while the corpus said missing-header → NOT-ESTABLISHED).** `txid` and
`blockHeader` are REQUIRED; a proof form (`proof` | `bump` | `beef` | `atomicBeef`) is
optional and, when absent, is treated as an **empty depth-0 legacy proof** (so the Merkle
comparison decides the outcome — a single-tx block where `txid == root` verifies, otherwise
FAILED). Authoritative header-state table:

| Input state | Outcome |
|---|---|
| `blockHeader` missing | MALFORMED |
| `blockHeader` empty (`""`) | MALFORMED |
| `blockHeader` malformed (non-hex, or length ≠ 160) | MALFORMED |
| `blockHeader` structurally valid | proceed (outcome from §G) |

Rationale: without a well-formed header the verification subject (this tx is committed to
*this* block) cannot even be stated, and PoW cannot be evaluated — so the input is MALFORMED,
not "evidence absent." NOT-ESTABLISHED is therefore **not** a top-level outcome for
well-formed envelopes; it remains a per-claim status for the permanent scope anti-claims
(§J). A missing *proof* is not NOT-ESTABLISHED either (see empty depth-0 rule above).

## C. Cryptographic invariants (must be true for ESTABLISHED)

1. `txid == SHA256d(rawTx)` (display-reversed). *verifier.html ~137, chain.html:502–504.*
   **explorer does not check this** (no `rawTx` binding) — explorer establishes TXID
   inclusion, not transaction-byte inclusion (documented in-tool).
2. The Merkle root computed **by walking up from `txid`** through the supplied siblings
   equals the `blockHeader`'s own merkle-root field (bytes 36–68). *bump.js merkleRoot walks
   from the txid offset; verifier compares to `headerMerkleRoot`; explorer seeds the walk at
   `r.txid.internal` and compares to `r.header.merkleRoot`.*
3. The block header satisfies its own target: `SHA256d(header) ≤ target(nBits)`.
4. Chain inclusion (when a chain is loaded) is tested on the **computed** hash of the exact
   verified header (`hashHeader(blockHeader)` / computed `r.header.blockHash`), never a
   self-declared value. The header hash commits to the merkle root, so a hashIndex hit means
   the chain holds the byte-identical header.

**Normative definitions (added after the conformance review found these were assumed, not
stated — they are standard Bitcoin but must not rely on unstated domain knowledge):**

- **`SHA256d(x)`** = `SHA256(SHA256(x))` over raw bytes.
- **Byte order.** The 80-byte header is little-endian on the wire: `version(4) prevHash(32)
  merkleRoot(32) time(4) bits(4) nonce(4)`. The header's merkle-root *field* (bytes 36–68)
  is little-endian ("natural"); reverse it to compare against a "display" root. `txid` and
  block hashes are **display** (big-endian) and are reversed to natural before hashing.
- **`target(nBits)` — compact-target decoding (Bitcoin consensus "nBits").** Let
  `exponent = nBits >> 24` and `mantissa = nBits & 0x007fffff`. Then
  `target = mantissa << (8 × (exponent − 3))` for `exponent ≥ 3`, else
  `target = mantissa >> (8 × (3 − exponent))`. (The `0x00800000` sign bit is never set in
  valid headers; an implementation may reject it.) `checkpoint_target = target(checkpoint
  nBits)`; the floor is `checkpoint_target × toleranceMultiplier`.
- **PoW comparison byte-order (security-critical).** `SHA256d(header)` yields 32 natural-order
  bytes; interpret them as a **little-endian** 256-bit unsigned integer for the `≤ target`
  comparison. (Interpreting big-endian inverts the test — a stranger who assumes big-endian
  builds a broken verifier. This is the single most important byte-order rule here.)
- **Merkle fold.** Working value starts as the natural-order txid. At each step concatenate
  `left || right` (32-byte natural values; `pos` selects which side the sibling is on — see
  §B), take `SHA256d`, and continue. The final value, reversed to display, is compared to the
  header's display merkle root.

## D. Structural invariants (must be true or the subject is MALFORMED)

Strict hex; bounds-checked readers; consume-all (no trailing bytes); BUMP/BEEF parse within
declared lengths; chain depth ≤ 32; Atomic-BEEF subject present, last, ancestors-only
(BRC-95). A structural failure means the input could not be interpreted as a well-defined
subject — it is **not** a statement that the transaction is invalid (see §I).

## E. Policy invariants (impose POLICY-REJECTED, not FAILED)

1. **Checkpoint anchor.** A loaded chain must be rooted at the embedded checkpoint
   (`939999` / `…bb54ef12` / `0x18227b71`). A chain anchored elsewhere is rejected.
2. **Per-header difficulty floor.** Every admitted header (standalone or every header of a
   loaded chain) must satisfy `target ≤ checkpoint_target × 8`. Enforced per header because
   `chainInclusion()` can report any admitted header as verified.
3. **Header timestamp sanity (GAP B resolution — Option A: in the contract).** The header
   timestamp (bytes 68–72, little-endian uint32, seconds) must satisfy
   `GENESIS_TIMESTAMP ≤ timestamp ≤ wallclock_now + MAX_FUTURE_SECONDS`, with
   `GENESIS_TIMESTAMP = 1231006505` (2009-01-03) and `MAX_FUTURE_SECONDS = 7200` (2h).
   Applies to every validated header (not just the tip); it affects header validity, not
   chain inclusion. A violation is **POLICY-REJECTED** (same bucket as the floor), never
   FAILED or MALFORMED. The upper bound uses the evaluator's wall clock and is the **one
   non-deterministic input** in the contract: two evaluators at very different times could
   disagree only for a header timestamped within `MAX_FUTURE_SECONDS` of *now*; for any
   historical header this never triggers, so it does not affect reproducibility in practice.
   Precedence note: because §G ranks FAILED above POLICY-REJECTED and PoW is checked before
   policy, a header that both fails PoW and has a bad timestamp is FAILED — so this rule is
   only observable on a PoW-valid header, which is why conformance verifies it at the
   policy-function level (an end-to-end case would require mining).

These are *local heuristics*, explicitly not consensus. A sub-floor-but-otherwise-valid
header is well-formed Bitcoin; the tool rejects it by **policy**. Result objects for a
policy rejection must carry the policy parameters that produced it (`checkpointNBits`,
`toleranceMultiplier`) so a different-appetite implementation is *differently-configured*,
not non-conformant.

## F. Outcome taxonomy (proposed canonical vocabulary)

Six per-claim outcomes. The task's five omitted `FAILED`; it is re-added because a root
mismatch / invalid PoW / `txid≠SHA256d(rawTx)` / `not_in_chain` must land somewhere that is
not `MALFORMED` (the input parsed fine) and not `POLICY-REJECTED` (nothing about policy).

| Outcome | Meaning | Examples |
|---|---|---|
| `ESTABLISHED` | Evidence present and supports the claim | root matches header; PoW valid; block in loaded chain |
| `FAILED` | Evidence present and cryptographically contradicts the claim | root mismatch; invalid PoW; `txid ≠ SHA256d(rawTx)`; `not_in_chain`; chain-load failure |
| `NOT-ESTABLISHED` | Not attempted by design (per-claim scope only) | `most-work-chain`; `current-spend-status` (never a top-level verdict for well-formed input) |
| `POLICY-REJECTED` | Well-formed and cryptographically valid, outside a declared local policy | sub-floor header; non-checkpoint anchor |
| `MALFORMED` | Input cannot be parsed into a well-defined subject | bad hex; trailing bytes; truncation; depth > 32; Atomic subject not last |
| `INDETERMINATE` | The verifier could not complete evaluation (internal/tool failure) | dependency threw; missing function; unexpected exception |

`INDETERMINATE` and `MALFORMED` are distinct on purpose: `MALFORMED` is a determinate
statement about the **input**; `INDETERMINATE` is the absence of a trustworthy statement
because the **tool** failed. The semantics-policy memo's own invariant ("must be visibly
distinguished") requires two outcomes, not one bucket.

**`NOT-ESTABLISHED` at top level (normative note).** The table above defines
`NOT-ESTABLISHED` as a *per-claim* outcome for claims not attempted by design, and §G states
it is "never a top-level verdict for well-formed input". That remains the normative rule. It
is **not** an unreachable value in an implementation: the reference classifier is total, so
input that is neither established, nor failed, nor policy-rejected, nor malformed, nor an
evaluation error falls through to `NOT-ESTABLISHED` (see §G, fallthrough). A conforming
implementation must make the same fallthrough rather than inventing a seventh label or
defaulting to a positive verdict; reaching it for well-formed input indicates incomplete
evidence, not a passing result.

## G. Verdict composition (deterministic top-level mapping)

The top-level verdict is derived from per-claim outcomes by **first-match precedence**.
Detection mechanism, not just priority, separates the first two:

1. **INDETERMINATE** — any evaluation step raised an exception that was not a declared
   parse-validation. The tool determined nothing; no other row may be reported.
2. **MALFORMED** — the parser returned a controlled "invalid input" result (§D). No claim
   is made about the transaction.
3. **FAILED** — any cryptographic/structural claim in §C returned `FAILED`
   (root mismatch, invalid PoW, `txid≠SHA256d(rawTx)`, `not_in_chain`, chain-load failure).
4. **POLICY-REJECTED** — no `FAILED`, but a §E policy claim rejected the evidence
   (sub-floor header, non-checkpoint anchor). Carries policy parameters.
5. **VERIFIED-ISOLATION** — all present cryptographic claims `ESTABLISHED`, but no chain
   loaded, so inclusion is `NOT-ESTABLISHED` by absence of evidence. PoW + root proven;
   inclusion **not** claimed. (This is today's amber "PoW in isolation".)
6. **VERIFIED** — all required claims `ESTABLISHED`, including chain inclusion.

**Fallthrough — `NOT-ESTABLISHED`.** The six rows above are a first-match ladder over
independent signals, so they are not exhaustive: nothing in rows 1–4 fired and the
cryptographic claims were not `ESTABLISHED`. The verdict is then `NOT-ESTABLISHED` — no
positive claim, no accusation against the evidence. This is a required seventh return value
for a total classifier, not a seventh semantic category; see §F. It must **fail closed**: it
is never rendered as, or coerced into, a positive verdict.

Scope anti-claims (`most-work-chain`, `current-spend-status`) are permanently
`NOT-ESTABLISHED` and **never** affect the top-level verdict (they are not-attempted).

Mapping to the five categories the task named:
A. successful → **VERIFIED**; B. valid but claim not established → **VERIFIED-ISOLATION**
(and the two scope anti-claims); C. policy rejection → **POLICY-REJECTED**;
D. malformed input → **MALFORMED**; E. verifier cannot determine → **INDETERMINATE**.

"Inclusion not proven" is **VERIFIED-ISOLATION**, never FAILED. "Failed verification" is
**FAILED**. These are different rows and must never share a field or a colour.

## H. Advisory model (separate axis; never changes the outcome)

Advisories annotate a verdict without altering it. Current example: "Low confirmations (N)"
(verifier.html:298), today wrongly encoded as `pass: null` alongside genuine
not-established states. Advisories belong on their own field (`advisories: [...]`), orthogonal
to the outcome. A VERIFIED result with a low-confirmations advisory is still VERIFIED.

## I. Indeterminate / error semantics

A verifier exception must never render as a claim about the evidence. Concretely (observed,
not hypothetical): a `ReferenceError` from an unstubbed dependency was caught and shown as
`✗ Header parse error`, i.e. presented as a verification failure. Under this spec that is
**INDETERMINATE**, and must be visibly distinct from `MALFORMED` (bad user input) and from
`FAILED` (evidence contradicts the claim).

**Specified adversarial test (IMPLEMENTED):** stub a required dependency (e.g.
`validateHeaderDifficulty` or `chainInclusion`) to `throw`; drive a normal, well-formed
envelope through `verify()`. Assert the outcome is `INDETERMINATE`; assert it is **not**
`FAILED`, **not** `POLICY-REJECTED`, **not** `VERIFIED`/`VERIFIED-ISOLATION`; assert the
diagnostic identifies an internal evaluation error distinct from parse failure. The test
matrix covers `ReferenceError` (undefined dependency), `TypeError` (unexpected dependency
throw), a missing proof library, malformed evidence (→ MALFORMED), and invalid PoW (→ FAILED).

**Boundary is semantic, not by JS error subclass.** Consensus/policy dependencies
(`verifyPoW`, `targetFromNBits`, `validateHeaderDifficulty`, `chainInclusion`) are invoked
through `evalDep()` (headers.js), which tags any throw with a named `EvaluationError`.
Classification keys on `error.name === 'EvaluationError'` — realm-safe (works across
vm/worker boundaries where `instanceof` does not) and independent of which accidental JS
subclass was thrown. Input-decoding (`parseHeader`, hex) and proof-evidence operations are
**not** wrapped, so they retain `MALFORMED`/`FAILED`. A missing proof library (`BUMP`/`BEEF`
undefined) is caught by an explicit presence guard → `INDETERMINATE`.

**Never degrade an internal error into an evidence/policy verdict.** A prior defect had
`buildAssurance` swallow a `validateHeaderDifficulty` throw into `{valid:false}`, which
misreported an evaluation failure (e.g. an undefined dependency) as a difficulty-floor
**POLICY-REJECTED**. Fixed: the dependency now propagates through `evalDep` to the boundary
and classifies as `INDETERMINATE`. Invariant: an evaluation exception must not leave a prior
success signal active and must not surface as `FAILED`/`POLICY-REJECTED`/`VERIFIED`.

## J. Scope boundaries (permanently NOT-ESTABLISHED)

`most-work-chain` and `current-spend-status` are `scope: 'not-attempted'` in every mode
(shared `SCOPE_ANTICLAIMS`, headers.js). Also out of scope: script/value-conservation for
unmined BEEF ancestors, blockchain sync, source discovery, machine-compromise protection,
constant-time guarantees, P2SH/multisig/testnet. Pre-checkpoint transactions can never be
chain-verified with the forward-from-checkpoint chain (permanently isolation-only).

## K. Evidence digest

**Recommendation: (B) verdict-relevant evidence identity**, not full input identity. The
digest exists so that "same digest ⇒ same verdict" is a meaningful claim; fields no verdict
path reads must not perturb it. It is an **evidence** digest, not a **result/verdict**
digest — agreement of evidence digests proves *same input*, never *same conclusion*.

Field classification (union across verifier/explorer/chain — a field is IN if **any**
consumer's verdict path reads it):

| Field | In digest? | Why |
|---|---|---|
| `txid` | **IN** | drives the Merkle walk; bound to `rawTx` |
| `rawTx` | **IN** | `txid == SHA256d(rawTx)` (verifier/chain) |
| `blockHeader` | **IN** | PoW target, merkle-root field, computed block hash |
| `proof` | **IN** | legacy Merkle path |
| `bump` | **IN** | **preferred over `proof`** for the root (verifier.html:214) |
| `beef` / `atomicBeef` | **IN** | alternative proof source the verifier reads |
| checkpoint identity (`height`+`hash`+`nBits`) | **IN** | anchor + floor basis; different anchor ⇒ different verdict |
| policy (`toleranceMultiplier`) | **IN** | POLICY-REJECTED depends on it |
| spec version | **IN** | framing; forbids cross-version collision |
| `vout` | **OUT** | advisory; no verdict path reads it |
| `satoshis` | **OUT** | advisory/display only |
| self-declared `blockHash` | **OUT** | never read; the **computed** hash (from `blockHeader`) is used |
| self-declared `blockHeight` | **OUT** | advisory/display only |
| `confirmations` | **OUT** | advisory axis (§H) |

Byte-framing requirements: keep the length-prefixed scheme `frame(s) = s.length + ':' + s`
(test-adversarial.js §B already proves it resists field-boundary collision, `pos`-case
leniency, and defaulted `pos`). Extend, don't replace. Required: (1) fixed declared field
order; (2) **absent ≠ empty** — a missing field must use a presence/absent sentinel so
`frame('bump')+frame('')` cannot collide with a genuinely empty bump; (3) include spec
version and checkpoint identity in the framing.

**Status: IMPLEMENTED** (explorer `canonicalInput`). Verified invariants: (A) differing
`bump` → differing identity; (B) absent ≠ empty for every optional field (`rawTx`, `bump`,
`beef`, `atomicBeef`) via a presence byte; (C) a committed context field (checkpoint,
tolerance, version, proof source) changes identity; (D) an excluded advisory/display field
(`vout`, `satoshis`, self-declared `blockHash`/`blockHeight`, `confirmations`) does **not**.

**Deliberate Replay-ID break.** Because the evidence digest now commits to
`rawTx`/`bump`/`beef`/`atomicBeef` + checkpoint identity + tolerance + spec version (and a
fixed field order), **Replay IDs produced by the pre-B4 digest do not equal those produced
by the current digest.** This is intentional — it closes the `bump`-blind collision where two
envelopes with identical `proof` and contradictory `bump` shared one Replay ID. No backward
compatibility is attempted or promised; old IDs must not be compared against new ones.

**Result/verdict digest: explicitly deferred.** It cannot exist until §F/§G and the result
shape are implemented, because it is a hash of the canonical result structure those define.
Shipping it now would freeze a shape that is about to change. State the deferral in the spec
so no reader mistakes the evidence digest for a verdict-agreement claim.

**Current-state finding (documented, not fixed this phase):** `canonicalInput`
(explorer.html:330) commits to only `txid`, `blockHeader`, `proof`. It ignores `bump` — yet
the verifier prefers `bump` over `proof`. Therefore two envelopes with identical `proof` and
contradictory `bump` fields receive **different verdicts under one Replay ID**. This is a
real identifier bug (a strictly larger subset omission than the README's documented "chain
state / outcome" deviation), and it is the concrete reason the evidence digest must be
extended before any conformance claim rests on it.

## L. Existing implementation mapping (legacy signals → shared enum)

**Status: the shared vocabulary is now emitted.** `lib/headers.js` defines the canonical
`OUTCOME` enum and a pure, total `classifyOutcome(signals)` implementing the §G precedence,
exported on the global/`window` object alongside `CHECKPOINT` and `SCOPE_ANTICLAIMS`. All
three consumers emit values from that one enum. The three encodings described below still
exist **as internal per-claim signals** — that is by design: they are the inputs the
classifier reduces. What no longer exists is three *outcome vocabularies*.

Per-consumer derivation as it stands:

| Consumer | Derives the outcome by | Note |
|---|---|---|
| `verifier.html` | calls shared `classifyOutcome` | accumulates `evaluationError` / `malformed` / `cryptoFailed` / `floorFailed` and passes them in |
| `explorer.html` | calls shared `classifyOutcome` | same signal set, plus `chainLoaded` / `inclusionVerified` |
| `chain.html` | **own mapper** `deriveChainOutcome` | emits the shared `OUTCOME` values, but maps its legacy `failureType` vocabulary itself rather than calling `classifyOutcome` |

`chain.html` is therefore conformant in *vocabulary* but not yet *converged on the shared
classifier*. It carries an inline fallback enum literal so the mapper still returns a defined
value if `lib/headers.js` fails to load. Converging it on `classifyOutcome` requires
re-deriving `malformed` / `failed` / `policyRejected` per hop and re-validating
`test-chain-malformed.js` and `fuzz-chain-browser.js`; it is a refactor, tracked as a
follow-up, and is **not** claimed as done.

The legacy per-claim signals the classifier consumes:

**verifier.html** — `checks[].pass ∈ {true,false,null}` accumulated into `allPassed`.
`pass:null` sites (all four): 198 "No block header (unconfirmed?)"; 264 "No Merkle proof";
285 "Chain inclusion NOT proven — no header chain loaded (isolation)"; 298
"Low confirmations". Mapping: 198,264 → `NOT-ESTABLISHED` (required external evidence
absent); 285 → `NOT-ESTABLISHED` (isolation); **298 → advisory axis (§H), not an outcome**.
`allPassed=false` → `FAILED` for §C claims, → `POLICY-REJECTED` for §E claims (the code does
not currently distinguish these two — a gap). Caught exception → currently `✗ parse error`;
should be `INDETERMINATE`.

**explorer.html** — `r.result.valid` = conjunction of structure, proof-safety, PoW,
difficulty-floor, root-match, chain-ok; `r.assurance.chainInclusion.status ∈
{unknown, verified, not_in_chain}` (headers.js:469/475/478); `chainLoadFailed` orthogonal;
`checks[].level ∈ {fail, soft}`. Mapping: `verified`→`ESTABLISHED`;
`not_in_chain`/`chainLoadFailed`→`FAILED`; `unknown`→`NOT-ESTABLISHED` (isolation);
floor rejection currently folded into `valid=false` → should be `POLICY-REJECTED`.

**chain.html** — per-hop `result` with `failureType` strings + `claimsNotEstablished`.
Per-hop failures map to `FAILED`/`MALFORMED` by cause; needs the same POLICY-REJECTED split.

The purpose of the enum was to collapse these three encodings into one shared vocabulary
(a `headers.js` const, like `SCOPE_ANTICLAIMS`) with an explicit per-consumer mapping, so
the drift this project exists to detect cannot recur. **Implemented**, with the `chain.html`
classifier convergence outstanding as described above.

The enum is a **label derived from existing per-claim signals**. It changes no accept/reject
decision and no cryptographic computation. Adding it did not make any previously-rejected
input acceptable.

### Scope-anticlaim regression invariant (proposed test, not the tautological one)

Do **not** assert `SCOPE_ANTICLAIMS` against itself. Instead: run each consumer's real
`verify()` and collect `result.claimsNotEstablished` in each mode
(isolation, chain-verified, failed).

**Implementation status, and a correction to this proposal.** The collection half is
implemented: `test/test-consumer-outcome-parity.js` drives all three shipped consumers on
identical evidence and reads `claimsNotEstablished` off the real `verify()` results.

The second half as originally written — assert the arrays are **deep-equal across all three
consumers** — is **superseded and must not be implemented in that form.** It assumed every
anti-claim is consumer-agnostic. That is no longer true: `chain.html` legitimately appends a
consumer-specific anti-claim (`chain-inclusion-this-consumer`, `scope: 'not-attempted'`)
because it loads no header chain and so can never attempt inclusion. A deep-equality
invariant would now fail on a correct implementation, and the obvious way to make it pass
again would be to delete a true scope boundary. The invariant that is actually in force:

- the **shared** `SCOPE_ANTICLAIMS` entries must appear in every consumer, with identical
  ids, `scope`, wording and relative order;
- a consumer may append entries of its own, which must also carry `scope: 'not-attempted'`;
- no anti-claim entry may contain an unconditional positive assertion (the defect corrected
  under B6 — see readiness notes);
- ordering remains semantically meaningful (fixed display order).

Wording drift, mutation and ordering changes in the shared set are still caught. Detection of
an *illegitimate* consumer-specific claim is now a weaker guarantee than deep equality gave,
and that reduction is deliberate and recorded here rather than hidden.

## M. Test / conformance claims (only what the tree demonstrates)

Corrections applied this pass (authorised): deleted the stale `explorer.html` transcript
line "Difficulty floor is advisory; chain-inclusion is informational" (contradicted the
gating at ~530 and the fix-comment at ~526); corrected the `generator.html` comment that
claimed BRC-74 was "validated against @bsv/sdk"; removed the README "all suites pass" and
"differential-tested against @bsv/sdk" claims and the License "@bsv/sdk conformance testing"
claim; reconciled the two contradictory README floor/isolation paragraphs to "fails closed,
not to isolation."

**`@bsv/sdk` status — a harness now exists; the SDK dimension has never been exercised here.**
The earlier statement in this section ("no `@bsv/sdk` differential harness exists") is
superseded on the first half and still correct on the second. Two harnesses are now in the
tree: `test/interop-beef-sdk.js` (registered in `npm test`) and `test/conformance-sdk.js`
(deliberately *not* registered — it is intended to be run by a developer who has installed the
SDK). `test/interop-beef-sdk.js` loads the SDK through a guarded `require('@bsv/sdk')` and, when
it is absent, prints `@bsv/sdk: NOT INSTALLED` and `SKIPPED (dimension unavailable, not
approximated)`. It always runs a machinery self-check using only the two in-repo
implementations, so the harness cannot silently become a no-op.

This repository declares **zero runtime dependencies** and `@bsv/sdk` is not installed, so in
every run recorded in this document the SDK comparison **skipped**. Therefore: **no claim of
`@bsv/sdk` conformance, interoperability or byte-identity is made or supported by this tree.**
What is established is production `lib/beef.js` against the independent in-repo oracle
`test/oracle-beef.js`. Third-party agreement remains unverified and requires a developer to
install the SDK and run the harness.

`validate.js` imports `crypto`, `./bump.js`, `./beef.js` only. Its TEST 1 oracle (`foldRoot`, validate.js:60) is a **second Merkle
implementation in the same file** — independent in execution path/logic, **not** in
authorship or conceptual origin. The one external anchor is the **BRC-74 published test
vector** (TEST 3).

`validate.js` assertion total is **non-deterministic** (observed 4334 / 4339 / 4346 on one
checkout) because TEST 4's 200 chains use unseeded `Math.random()` for chain length, input/
output counts, and script lengths, varying how many asserts execute. **No fixed total is
cited.** Recommendation: **retain the random test, report structure** (option A) — the
randomness is genuine fuzzing value; seeding it would trade coverage for a cosmetic number.
If a reproducible number is ever needed, add an opt-in seed, don't seed by default. Verified
deterministic structure: 20 tree shapes (`2,3,4,5,6,7,8,9,15,16,17,31,64,100,255,511,1000,
2048,4095,4096`) × 8 trials, with `min(n,6)` indices per trial → **880 BUMP-vs-oracle
iterations (deterministic)**; TEST 2 tamper/unknown-txid; TEST 3 BRC-74 vector; TEST 4
**200** random tx-chains (trial count deterministic, per-trial asserts not); 0 failures.

## N. Independent implementation requirements

To reproduce the same semantic result, `headers-node` needs: the checkpoint constant
(height/hash/nBits); the per-header floor rule and ×8 tolerance; the BUMP/BEEF/legacy proof
parse + txid-anchored Merkle walk; the header-hash-commits-to-root chain-membership test;
the §F outcome enum and §G composition; the §H advisory axis; the §K evidence-digest field
set and byte-framing; and the §C/§D/§E invariants. It does **not** need most-work, spend
status, or script evaluation.

**Chain-index trust boundary (verify() must consume only loader-produced chain state).**
Chain membership may establish a `VERIFIED` inclusion verdict only when the index is the
output of the checkpoint-anchored, predecessor-validated loader (§O). An arbitrary
caller-built `Map(headerHash → height)` is **not** equivalent to a loader-produced index and
must never establish trusted membership. Enforcement differs by surface, and both are
conformant: the production explorer/verifier enforce it **structurally** — the index is a
closure variable assigned only from `verifyHeaderChain` output and nulled on load failure, so
no caller can inject one; `verify()` takes no index parameter. The parameterized
reimplementation API (`headers-node-independent`) enforces it **explicitly** — `loadChain`
registers its index in a module-private, unforgeable registry (a `WeakSet`, which reflection
cannot observe or add to), and `verify()` refuses any unregistered index for membership
(failing closed to `VERIFIED-ISOLATION` with a `chain-index-refused` advisory) unless the
caller passes an explicit `trustIndex:true` assertion. A raw index therefore can never
silently produce `VERIFIED`. Note the security-correct consequence: "not in chain → FAILED"
is concludable only from a *trusted* chain; an untrusted index yields isolation, not FAILED.

---

## O. Chain loading and anchoring (the `headers.bin` → anchored index)

The §C-4 membership test consumes a `hashIndex` (map of computed **display** header hash →
height) that must be **anchored at the checkpoint**. This section specifies how that index is
produced from a raw `headers.bin`, so a from-scratch implementation is complete. (Reference:
`verifyHeaderChain`, headers.js.)

**File format.** A 40-byte prefix followed by `headerCount` consecutive 80-byte headers:

| Offset | Size | Field | Encoding |
|---|---|---|---|
| 0 | 4 | `anchorHeight` | uint32 little-endian |
| 4 | 32 | `anchorHash` | 32 bytes in **display** (big-endian) order, i.e. hex equals the checkpoint hash string |
| 36 | 4 | `headerCount` | uint32 little-endian |
| 40 | 80·N | headers | consecutive 80-byte block headers (§C byte layout) |

Reject as MALFORMED if `length < 40` or `length < 40 + headerCount·80` (truncated).

**Anchoring — fail closed (the single thing pinning the chain to the real network).**
`(anchorHeight, anchorHash)` MUST equal the embedded checkpoint `(height, hash)`. If it does
not, **reject the chain** (do not load it) — a chain not rooted at the trusted checkpoint is
refused, never accepted as advisory. A caller may pass an explicit opt-in weaker mode
(`requireCheckpoint:false`) but the default and specified behaviour is to fail closed. When a
chain fails to load for any reason in this section, the verifier does **not** silently
downgrade to isolation *inside* a loaded-chain verdict — it fails closed (a chain was supplied
and is unusable); isolation means *no chain supplied* (§B / §G-5).

**Per-header processing.** Initialise `prevHash = anchorHash`. For `i = 0 … headerCount−1`
(height `= anchorHeight + 1 + i`):
1. Parse the 80-byte header (§C). A parse failure is MALFORMED.
2. **Linkage:** the header's `prevBlock` (display) MUST equal `prevHash`; else reject
   ("chain break at height").
3. **PoW:** the header's computed display hash, as a 256-bit integer, MUST be `≤ target(nBits)`
   (§C PoW rule); else reject ("invalid PoW at height").
4. Record `hashIndex[computedDisplayHash] = height`; set `prevHash = computedDisplayHash`.

**Whole-chain difficulty floor (policy §E-2, per header).** *Every* admitted header must
satisfy `target(nBits) ≤ checkpoint_target × toleranceMultiplier` — enforced for every header,
not just the tip, because the membership test can report any admitted header as verified;
this prevents amortising one floor-difficulty tip across many cheap forged intermediates. A
violation fails closed (accepted trade-off: a genuine >8× drop is rejected rather than risk a
false accept; documented false-negative-over-false-positive).

**Output.** `{ hashIndex, tipHeight, tipHash, anchor }`. Only `hashIndex` is required by §C-4;
the rest is informational. The loader performs no most-work / reorg selection (§J).



| Test | Deterministic | Reproduces clean | Tests | Browser | Mainnet data | Conformance-suitable |
|---|---|---|---|---|---|---|
| `lib/bump.js` self-test | yes | yes (in my tree) | BUMP root/serialize | no | no | yes (vector) |
| `lib/beef.js` self-test | yes | yes | BEEF/Atomic round-trip, subject validation | no | no | yes |
| `test/test-audit-fixes.js` | yes | yes (14/14) | checkpoint, raise-only floor, parser strictness, verifyMined | no | no | partial |
| `test/test-adversarial.js` | yes | yes (46/46) | forged chain, canonicalization, floor policy G1–G6, anti-claims H1–H7, UI1–UI4, Atomic F | no | no | yes |
| `validate.js` | **no (count)** / yes (structure) | passes; total varies | BUMP vs in-file oracle, BRC-74 vector, tamper, BEEF fuzz | no | no | structure only |
| `tests.html` | yes | 82/82 via Node DOM-stub | BUMP/BEEF/chain-inclusion vectors | yes (real) | no | yes |
| `tests-mainnet.html` | yes | 31/31 via Node DOM-stub | real-mainnet verification | yes (real) | yes | yes |
| `test/verify-real-envelope.js` | yes | yes | end-to-end real envelope | no | yes (fixture) | yes |
| `test-generator.js` | count non-det (fuzz) | **runs; 325/326** — 1 stale title regex | TSC→BUMP vs Node-crypto oracle (160 conv/16 shapes), attachBump self-verify guard, generator→verifier round-trip | no | no | structure yes |
| `test-integration.js` | yes | **runs; 5/6** — 1 stale title regex | wired verifier on good/tampered/legacy envelopes | no | no | partial |
| `test-chain.js` | yes | **won't run as-shipped** (extraction boundary missing `chainLoadFailed`); with a 1-line harness stub → 13/19 | explorer chain-inclusion states + verifier states | no | fixture | explorer part yes |

"Reproduces clean" for browser suites means via the Node DOM-stub harness used this session,
**not** a real browser. Real-browser is unverified here.

**Drift classification (measured, not reported).** The three previously-missing suites were
run against the current tree. **No product defect was found; every failure traces to a
deliberate hardening change the harness never tracked:**
- `VALID MERKLE PROOF` (the old success title) is gone by design — the verdict was split into
  `VALID — INCLUSION PROVEN` / `VALID PROOF — INCLUSION NOT PROVEN` (verifier.html:302–308).
  Three assertions across the suites grep the stale string.
- `test-chain.js` extracts `verify()` from `explorer.html` by text slice; that fragment now
  reads `chainLoadFailed`, an outer-scope variable added by the fail-closed chain-load fix,
  which the slice omits → `ReferenceError`. Binding it (`chainLoadFailed=false`) lets the suite
  run; the explorer chain-inclusion assertions then pass in full (status unknown/verified/
  not_in_chain; valid true/true/false; correct reason and height; identifier stability across
  all three chain states).
- The hardcoded `replayId` constant `C300073D26E61EE8` is stale, but the suite's own
  cross-state assertion (identifiers identical across all three chain states) passes — i.e.
  identifiers **do** reproduce; only the pinned constant is outdated.
- Three verifier check-strings the suite greps (`no header chain loaded`,
  `Block in header chain (height N)`, `Block NOT in loaded header chain`) are all present in
  `verifier.html`; those failures are the suite's verifier vm-harness not capturing them, not
  missing behaviour.

These are harness-maintenance items (update the stale title regex, refresh or drop the pinned
replayId, extend the extraction boundary / stub `chainLoadFailed`), not conformance findings.
Until refreshed, they should not be cited as passing suites.

---

## Final independence test (Part K)

> Could a competent independent developer implement `headers-node` from this document alone
> (without reading the JS) and know what counts as the same semantic result?

*This section previously answered **NO — not yet**, on the grounds that §F/§G were proposed
rather than implemented. Items 1–5 below have since landed; the answer has changed, and the
reasons it is still not an unqualified yes are different ones.*

**Qualified yes on shape; unproven in fact.** The result shape an independent build must
produce is now emitted by this tree, so a comparison is possible where previously it was not.
Former ambiguities, with current status:

1. **Outcome enum and verdict composition (§F/§G)** — **implemented.** One shared vocabulary
   (`OUTCOME`) and one precedence ladder (`classifyOutcome`) in `lib/headers.js`, emitted by all
   three consumers. The legacy per-claim encodings survive as classifier *inputs*, not as
   outcome vocabularies (§L).
2. **`INDETERMINATE`** — **emitted**, via tagged `EvaluationError` detection in all three
   consumers, and admitted to the documented-outcome set the differential fuzzers enforce
   (`test/fuzz-browser.js:136`, `test/fuzz-verifier-browser.js:159`). *Residual:* there is no
   dedicated §I suite asserting every `INDETERMINATE` path; coverage is incidental
   (`test/test-chain-malformed.js`) plus fuzz admission. The §I test remains worth writing.
3. **`POLICY-REJECTED` distinguished from `FAILED`** — **implemented** in all three consumers
   (readiness B2).
4. **Evidence digest** — **field set and framing implemented** (§K); `canonicalInput` commits
   `bump`/`beef`/`atomicBeef` with an absent-vs-empty sentinel, so the Replay ID is no longer
   ambiguous under `bump`/`proof` disagreement. *Residual:* the framing is pinned by this
   implementation and not cross-validated. The **result** digest remains deferred.
5. **Advisory axis (§H) separated** — **implemented** (readiness B5).
6. **Structural/ordering guarantees of `claimsNotEstablished`** — **partially addressed.**
   `test/test-consumer-outcome-parity.js` collects them from real `verify()` results across all
   three consumers rather than asserting a const against itself. The originally proposed
   cross-consumer deep-equality invariant is superseded and must not be implemented as written
   (§L explains why, and what replaced it).

So items 1, 3 and 5 are closed; 2, 4 and 6 are closed in the respect that blocked conformance
and carry the named residuals above.

**Why this is still not an unqualified YES.** Everything above is this tree assessing itself.
The question asks what an *independent* developer would conclude, and no independent developer
has been asked. The specification and the verifiers derived from it share an author, and
`headers-node-independent` is a reimplementation *against this document*, so agreement between
them demonstrates internal consistency and nothing about external correctness. No independent
third-party audit has been performed, and third-party (`@bsv/sdk`) agreement has never been
exercised in this environment (§M). An independent build can match the **cryptographic** result
with confidence; whether it would match the **semantic envelope and the digest bytes** is
specified, plausible, and untested.

---

# CONFORMANCE CONTRACT — FROZEN

This section freezes the **target** semantics. It is the contract an independent
`headers-node` must reproduce. "Frozen" means the *decisions* below are settled; it does
**not** mean the current code already emits them. As of the readiness review recorded below,
the outcome enum and the precedence ladder *are* emitted by all three consumers (§L); the
remaining divergences are named in that section. Each decision is traceable to current
behaviour cited above.

### Inputs
An envelope (§B): `txid`, `vout`, `satoshis`, `rawTx`, `blockHeader`, and at least one proof
form (`proof` | `bump` | `beef`/`atomicBeef`); optional self-declared `blockHash`/
`blockHeight`/`confirmations`. Optional external evidence: a checkpoint-anchored
`headers.bin`. Policy inputs: checkpoint (`height`,`hash`,`nBits`) and floor tolerance ×8.

### Evidence (authoritative)
Authoritative: `rawTx`, `blockHeader`, the selected proof, and the loaded chain. Proof
selection order is fixed: `bump` → `beef`/`atomicBeef` → legacy `proof`. Self-declared
`blockHash`/`blockHeight`/`satoshis`/`vout`/`confirmations` are **not** authoritative
(display/advisory only); the block hash used everywhere is the **computed** `SHA256d(blockHeader)`.

### Cryptographic requirements
1. `txid == SHA256d(rawTx)` (verifier, chain; **not** explorer — see Scope).
2. Merkle root, computed by walking up **from `txid`**, equals `blockHeader`'s root field.
3. `SHA256d(blockHeader) ≤ target(nBits)`.
4. Chain inclusion (if a chain is loaded) tested on the **computed** header hash.

### Policy requirements
1. Loaded chain must be anchored at the embedded checkpoint.
2. Every admitted header (standalone and every chain header) satisfies
   `target ≤ checkpoint_target × 8`. Heuristic, not consensus; parameters travel with the result.

### Outcomes (canonical enum — six, confirmed necessary and distinguishable)
`ESTABLISHED` (per-claim) / `VERIFIED` (top-level) · `FAILED` · `NOT-ESTABLISHED` ·
`POLICY-REJECTED` · `MALFORMED` · `INDETERMINATE`. Definitions and the reasons none can be
merged are in §F. **Refinement confirmed this pass:** lineage contradictions
(`ORDERING_INVALID` — reversed/unlinked chain) are `FAILED` (evidence evaluated, claim
contradicted), not `MALFORMED` (which is reserved for inputs that cannot be parsed at all).

### Verdict composition (deterministic; frozen precedence)
First match wins, separated by **detection mechanism** for the top two:
1. `INDETERMINATE` — an evaluation step raised an exception that was **not** a declared
   parse-validation. (If the tool threw, it may not claim the input is malformed.)
2. `MALFORMED` — the parser returned a controlled "invalid input" result.
3. `FAILED` — any §C/lineage claim contradicted (root mismatch, invalid PoW,
   `txid≠SHA256d(rawTx)`, `not_in_chain`, chain-load failure, `ORDERING_INVALID`).
4. `POLICY-REJECTED` — no `FAILED`, but a §E policy rejected well-formed valid evidence
   (sub-floor header, non-checkpoint anchor); carries policy parameters.
5. `VERIFIED-ISOLATION` — all present cryptographic claims `ESTABLISHED`, no chain loaded
   (inclusion `NOT-ESTABLISHED` by absence). PoW+root proven; inclusion not claimed.
6. `VERIFIED` — all required claims `ESTABLISHED`, including chain inclusion.
Scope anti-claims are permanently `NOT-ESTABLISHED` and never affect the top-level verdict.

### Advisories (separate axis; never change the outcome)
`confirmations < 6` (low-confirmations) is advisory: today a `pass:null` check that does not
affect `allPassed`, i.e. advisory-in-effect. Frozen: advisories live on their own field and
never alter the outcome. Isolation is **not** an advisory — it is the `VERIFIED-ISOLATION`
outcome. Chain-inclusion status **is** outcome-bearing, not advisory.

### Scope boundaries (permanently NOT-ESTABLISHED)
`most-work-chain`; `current-spend-status` / current UTXO membership; current chain state.
Per-consumer: **explorer establishes TXID inclusion, not transaction-byte inclusion** (it
performs no `rawTx↔txid` binding) — an independent explorer-equivalent must make the same
narrower claim and must not report `VERIFIED` in a way that implies a specific transaction.

### Evidence digest (verdict-relevant identity — field set frozen; framing implemented, not independently cross-validated)
IN: `txid`, `rawTx`, `blockHeader`, `proof`, `bump`, `beef`/`atomicBeef`, checkpoint identity
(`height`+`hash`+`nBits`), policy (`toleranceMultiplier`), spec version.
OUT (advisory / never read by a verdict path): `vout`, `satoshis`, self-declared `blockHash`,
self-declared `blockHeight`, `confirmations`.
Framing: length-prefixed `frame(s)=s.length+':'+s`, fixed field order, **absent ≠ empty**
(presence sentinel), checkpoint+version included. Distinct from a **result digest** (deferred).
This is an evidence-identity claim only: equal digest ⇒ same inputs, **never** same verdict.

**Framing as implemented** (`explorer.html`, `canonicalInput` / `frame` / `frameOpt`). The
optional-field sentinel is `frameOpt(name,val) = frame(name) + ('0' | '1' + frame(val))`, so an
absent field contributes `frame(name)+'0'` and an empty-string field contributes
`frame(name)+'1'+'0:'` — absent and empty are distinguishable, as required. Field order is
fixed by the function body: `v`/spec-version, `checkpoint` (`height/hash/nBits-hex`),
`tolerance`, `txid`, `header`, then optional `rawTx`, `bump`, `beef`, `atomicBeef`, then
`proof` (canonicalised length, then each `hash`+`pos`). Hex is lower-cased before framing.

This closes the field-set half of blocker B4: the digest now commits to `bump`, `beef` and
`atomicBeef`, so two envelopes with identical `proof` and contradictory `bump` no longer share
a Replay ID. **Limitation, stated rather than glossed:** the framing above is the framing of
*this* implementation. It has not been reproduced by a genuinely independent implementation, so
it is a pinned reference framing, not a cross-validated interoperable one. An independent build
that agrees on §C/§D/§E could still disagree on the digest bytes.

### Conformance requirement
An implementation conforms if, for every corpus case, it (a) computes the identical
cryptographic result (§C/§D/§E), (b) emits the identical top-level outcome under the
precedence above, (c) emits the identical evidence digest once byte-framing is finalized, and
(d) makes no scope claim beyond §J. Policy parameters may differ but must be **declared**;
two implementations with different tolerances agree on every consensus claim and differ only
in a declared `POLICY-REJECTED` threshold.

### Adversarial corpus — expected outcomes (frozen)
| # | Case | Expected top-level |
|---|---|---|
| 1 | valid inclusion (chain has block) | `VERIFIED` |
| 2 | valid isolation (no chain) | `VERIFIED-ISOLATION` |
| 3 | wrong Merkle sibling | `FAILED` (root mismatch) |
| 4 | wrong TXID (`txid≠SHA256d(rawTx)`) | `FAILED` (explorer: N/A — no binding) |
| 5 | wrong header (root≠proof root) | `FAILED` |
| 6 | intermediate sub-floor header | `POLICY-REJECTED` (emitted; see readiness B2) |
| 7 | chain membership failure | `FAILED` (`not_in_chain`) |
| 8 | malformed envelope (bad hex/trailing/depth>32/atomic-subject-not-last) | `MALFORMED` |
| 9 | missing / empty / malformed header | `MALFORMED` (GAP A: header is required) |
| 10 | missing proof (multi-tx block) | `FAILED` (absent proof = empty depth-0; root = txid ≠ header root) |
| 11 | internal verifier exception | `INDETERMINATE` (emitted; see readiness B3) |
| 12 | advisory-only low confirmations | outcome unchanged + advisory flag |
| 13 | same evidence, different chain state | outcome may differ; **evidence digest identical** |
| 14 | equivalent evidence | identical semantic result + identical evidence digest |

---

# Conformance readiness

*Reviewed against `f4f3d3b306e671206bcb28c1cc399b9ace56d7f9`. Line cites are from that
commit. This section replaces an earlier revision that read **NOT READY** and listed B1–B6
as open; that revision was written before the labelling work landed and had become stale.*

**Cryptographic contract: specified.** §C/§D/§E plus the corpus determine the cryptographic
result, as before.

**Semantic envelope: now emitted, with two named residuals.** The shared enum and the §G
precedence ladder are implemented and all three consumers emit them. The honest summary is
**not** "ready" and **not** "not ready": the labelling blockers B1–B6 are addressed, and what
remains open is independent reproduction — which no amount of work inside this tree can supply.

| # | Blocker | Status | Evidence at `f4f3d3b` |
|---|---|---|---|
| B1 | three legacy outcome encodings | **addressed** (one residual) | `OUTCOME` (`lib/headers.js:538`), `classifyOutcome` (`:557`), exported (`:589–590`); `verifier.html:324` and `explorer.html:610` call it; `chain.html:749` `deriveChainOutcome` emits the same enum via its own mapper |
| B2 | POLICY-REJECTED not distinguished from FAILED | **addressed** | `policyRejected` signal at `explorer.html:615`, `verifier.html:326`; `chain.html:566` sets `POLICY_REJECTED`, mapped at `:758`; precedence row 4 |
| B3 | INDETERMINATE not emitted; exceptions mislabeled | **addressed** | `isEvaluationError` tagging: `explorer.html:489–492`, `:581–584`; `verifier.html:201, 220, 302, 325`; `chain.html:751` |
| B4 | evidence digest incomplete and `bump`-blind | **addressed** (field set + framing); interop unverified | `frameOpt` (`explorer.html:332`), `canonicalInput` (`:342`) now commits `rawTx`/`bump`/`beef`/`atomicBeef` with an absent-vs-empty sentinel; see §K |
| B5 | advisory axis not separated | **addressed** | dedicated `advisories: []` (`explorer.html:399`, populated `:407`); `advisory: true` flag and separate render axis (`verifier.html:312, 377, 383–385`) |
| B6 | cross-consumer representation divergence | **addressed** | `chain.html:755` returns `VERIFIED_ISOLATION` where it previously returned `VERIFIED`; local `CHAIN_SCOPE_ANTICLAIMS` (`:219`) adds `chain-inclusion-this-consumer` (`:221`), appended on both return paths (`:776`); the shared `most-work-chain` entry (`lib/headers.js:492`) no longer opens with an unconditional positive assertion |

**The B6 correction, recorded.** `chain.html` verifies lineage, Merkle inclusion and
proof-of-work per hop but loads **no header chain**. It previously returned `VERIFIED` on a
valid result, asserting a checkpoint-anchored inclusion it had never attempted; §G step 5
applies and step 6 is unreachable for this consumer. Two things were corrected together: the
verdict, and the shared scope anti-claim whose `detail` opened by asserting that "a
checkpoint-anchored, linked, PoW-valid chain under the configured difficulty policy is
verified" — text that reached the rendered verdict and `exportJSON()`, inside a block headed
"This tool does NOT establish". A scope anti-claim must carry no unconditional positive
assertion. `test/test-chain-malformed.js` expected `VERIFIED` for the valid single-hop case;
that expectation encoded the defect and was corrected as part of the fix, not relaxed to make
a test pass.

### Residuals — open, and not to be described as closed

- **R1 — `chain.html` has not converged on the shared classifier.** It emits the shared
  vocabulary through its own `deriveChainOutcome` mapper. Vocabulary divergence is resolved;
  *derivation* divergence is not. Two mappers can drift, which is the class of defect B6 was.
  Mitigated, not eliminated, by `test/test-consumer-outcome-parity.js`, which asserts the three
  consumers agree on identical evidence. Converging it is a refactor (§L).
- **R2 — the evidence-digest framing is pinned, not cross-validated.** §K records the exact
  framing the reference implementation uses. No independent implementation has reproduced it.
- **R3 — no independent third-party reproduction, and shared authorship.** The specification
  and the spec-derived verifiers in this tree share an author. `headers-node-independent`
  is a reimplementation against this specification, not an independent development; agreement
  between them is evidence of internal consistency, not of external correctness. No
  independent third-party security audit has been performed.
- **R4 — `@bsv/sdk` agreement is unverified.** The harness exists and skips; see §M.

### What "ready" would require

Not more code in this tree. It requires a developer with no hand in this specification to
build a verifier from §§A–O alone, run the frozen corpus, and agree on every top-level
outcome *and* the digest bytes. Until that happens the correct statement is: the contract is
specified and internally consistent, and its conformance claims are untested against an
outside party.

## Final question

> Given only the frozen specification, could another competent developer implement
> `headers-node` and know the result for every important adversarial case?

**Cryptographic inclusion result: YES** — §C/§D/§E plus the corpus fully determine cases
1–5, 7–10, 13–14 at the cryptographic level.

**Full semantic result: specified, and unproven.** The gaps that made this a clear "NO" in the
earlier revision — case 6 (`POLICY-REJECTED` vs `FAILED`), case 11 (`INDETERMINATE`), and the
`bump`-blind digest (B4) — are now realised in the code and recorded above with line cites, and
the digest framing is pinned in §K. A developer following §§A–O should now be able to derive
the same top-level outcome for every corpus case.

That is a statement about the specification, not a demonstration. It has not been tested the
only way it can be: by someone outside this work building to the spec and comparing results
(residuals R2–R4). So the answer is **not** "YES" — it is "the specification no longer
knowingly withholds what an implementer needs, and whether that is sufficient remains
unverified." The remaining convergence item (R1) is a bounded refactor, not a missing
capability.
