# Merkle Envelope Tools — Verification Semantics (specification precursor)

Status: **proposed**. This document specifies the *target* semantics for an independent
implementation (`headers-node`) and a conformance corpus. Where it describes what the code
does **today**, it says so explicitly and cites the location. Nothing here changes
production verification logic; the only code/doc changes made alongside it are the
authorised factual corrections listed in §M.

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

## L. Existing implementation mapping (current → proposed)

Three overlapping encodings exist today; none is the enum above.

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

The purpose of the enum is to collapse these three encodings into one shared vocabulary
(a `headers.js` const, like `SCOPE_ANTICLAIMS`) with an explicit per-consumer mapping, so
the drift this project exists to detect cannot recur. **Not implemented in this phase.**

### Scope-anticlaim regression invariant (proposed test, not the tautological one)

Do **not** assert `SCOPE_ANTICLAIMS` against itself. Instead: run each consumer's real
`verify()` and collect `result.claimsNotEstablished` in each mode
(isolation, chain-verified, failed). Assert the collected arrays are **deep-equal across all
three consumers and all modes** — same ids, same `scope`, same wording, same order — so the
test catches wording drift, missing/extra claims, mutation, consumer-specific claims, and
ordering changes. Ordering is treated as semantically meaningful (fixed display order).

## M. Test / conformance claims (only what the tree demonstrates)

Corrections applied this pass (authorised): deleted the stale `explorer.html` transcript
line "Difficulty floor is advisory; chain-inclusion is informational" (contradicted the
gating at ~530 and the fix-comment at ~526); corrected the `generator.html` comment that
claimed BRC-74 was "validated against @bsv/sdk"; removed the README "all suites pass" and
"differential-tested against @bsv/sdk" claims and the License "@bsv/sdk conformance testing"
claim; reconciled the two contradictory README floor/isolation paragraphs to "fails closed,
not to isolation."

**No `@bsv/sdk` differential harness exists.** A whole-tree search finds `@bsv/sdk` only in
prose/comments, never imported or executed. `validate.js` imports `crypto`, `./bump.js`,
`./beef.js` only. Its TEST 1 oracle (`foldRoot`, validate.js:60) is a **second Merkle
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

---

## Test inventory (reproducible facts only)

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

**NO — not yet.** This is a precursor; the target semantics are specified but not yet
realised in code, so an independent build would produce a differently-shaped result that
cannot be checked for "same semantic result." Remaining ambiguities to close first:

1. **The outcome enum and verdict composition (§F/§G) are proposed, not implemented.** The
   code still uses three overlapping encodings (`checks[].pass/level`,
   `chainInclusion.status`, `pass:null`). Until one shared vocabulary is emitted in results,
   there is nothing byte-stable to conform to.
2. **`INDETERMINATE` does not exist.** Internal exceptions still surface as failure-like
   states; the §I test is unwritten.
3. **`POLICY-REJECTED` is not distinguished from `FAILED`** in any consumer; sub-floor
   rejection is currently folded into a generic invalid verdict, and policy parameters are
   not emitted.
4. **The evidence digest is under-specified in code.** `canonicalInput` omits `bump`
   (and more), the field set and absent-sentinel framing in §K are not implemented, and the
   result digest is deferred. The current Replay ID is ambiguous (same id, different verdict
   under `bump`/`proof` disagreement).
5. **The advisory axis (§H) is not separated** from outcome (`low confirmations` still rides
   `pass:null`).
6. **Structural/ordering guarantees of `claimsNotEstablished`** are asserted only via a
   shared const, not via the cross-consumer result-object invariant in §L.

Closing items 1–5 (implementation) and adding the §L and §I tests would flip this to YES.
Each is a defined, bounded task; none requires new verification capability. Until then, an
independent implementation can match the **cryptographic** result (that part is fully
specified in §C/§D/§E) but not the **semantic envelope** (the outcome/verdict/digest shape).

---

*This document specifies target semantics and records current behaviour with citations. It
introduces no verification capability and changes no verification logic. The author of this
spec also wrote the code it describes; an independent reviewer remains owed.*

---

# CONFORMANCE CONTRACT — FROZEN

This section freezes the **target** semantics. It is the contract an independent
`headers-node` must reproduce. "Frozen" means the *decisions* below are settled; it does
**not** mean the current code already emits them (see Conformance readiness — several are
proposed, and the code still uses three legacy encodings). Each decision is traceable to
current behaviour cited above.

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

### Evidence digest (verdict-relevant identity — field set frozen; byte-framing pending)
IN: `txid`, `rawTx`, `blockHeader`, `proof`, `bump`, `beef`/`atomicBeef`, checkpoint identity
(`height`+`hash`+`nBits`), policy (`toleranceMultiplier`), spec version.
OUT (advisory / never read by a verdict path): `vout`, `satoshis`, self-declared `blockHash`,
self-declared `blockHeight`, `confirmations`.
Framing: length-prefixed `frame(s)=s.length+':'+s`, fixed field order, **absent ≠ empty**
(presence sentinel), checkpoint+version included. Distinct from a **result digest** (deferred).
This is an evidence-identity claim only: equal digest ⇒ same inputs, **never** same verdict.

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
| 6 | intermediate sub-floor header | `POLICY-REJECTED` (target: today `FAILED` — blocker B2) |
| 7 | chain membership failure | `FAILED` (`not_in_chain`) |
| 8 | malformed envelope (bad hex/trailing/depth>32/atomic-subject-not-last) | `MALFORMED` |
| 9 | missing / empty / malformed header | `MALFORMED` (GAP A: header is required) |
| 10 | missing proof (multi-tx block) | `FAILED` (absent proof = empty depth-0; root = txid ≠ header root) |
| 11 | internal verifier exception | `INDETERMINATE` (target: today mislabeled — blocker B3) |
| 12 | advisory-only low confirmations | outcome unchanged + advisory flag |
| 13 | same evidence, different chain state | outcome may differ; **evidence digest identical** |
| 14 | equivalent evidence | identical semantic result + identical evidence digest |

---

# Conformance readiness — CONFIRMED THIS PASS

**NOT READY.** The cryptographic contract (§C/§D/§E) is fully specified and an independent
build could match it today. The **semantic envelope** is not yet emitted by the code. Blockers,
each confirmed against the current tree this pass:

- **B1 — three legacy outcome encodings persist.** verifier `checks[].pass∈{true,false,null}`
  + title; explorer `r.result.valid` + `chainInclusion.status∈{unknown,verified,not_in_chain}`;
  chain `failureType∈{STRUCTURE_INVALID,ORDERING_INVALID,TXID_MISMATCH,TX_PARSE_ERROR,POW_INVALID,MERKLE_MISMATCH}`.
  None is the frozen enum. Until one shared vocabulary is emitted, there is nothing byte-stable
  to conform to.
- **B2 — POLICY-REJECTED not distinguished from FAILED.** Floor rejection is a plain
  `pass:false` (verifier.html:185) / folded into `valid=false` (explorer.html:537); chain uses
  `POW_INVALID`. Sub-floor (well-formed, valid) is currently indistinguishable from a crypto
  failure. Fails closed correctly, but the outcome label is wrong for conformance.
- **B3 — INDETERMINATE not emitted; exceptions mislabeled.** chain.html:800 catches a hop
  exception and returns `STRUCTURE_INVALID` (→ MALFORMED); verifier renders dependency
  exceptions as `✗ parse/chain error` (→ FAILED-like). Both violate "a tool failure is not a
  claim about the evidence." §I test unwritten.
- **B4 — evidence digest incomplete and `bump`-blind (real defect).** `canonicalInput`
  (explorer.html:330) commits to `txid`/`blockHeader`/`proof` only; the verifier **prefers
  `bump`**. Two envelopes with identical `proof` and contradictory `bump` → different verdict,
  **same Replay ID**. This is a genuine semantic defect and a **hard blocker to
  cross-implementation digest compatibility**. Field set is frozen above; the code does not yet
  implement it, and absent-sentinel/field-order framing is unpinned. (Not fixed this pass, per
  instruction.)
- **B5 — advisory axis not separated in representation.** Low-confirmations rides `pass:null`
  on the checks channel rather than a dedicated advisory field.
- **B6 — cross-consumer representation divergence.** The explorer `rawTx↔txid` non-binding is an
  **intentional scope difference** (keep, but spec it — done). The differing outcome encodings
  (B1) and the exception mislabeling (B3) are **genuine semantic inconsistencies**, not mere
  presentation.

Non-blockers (classified, not to be "fixed"): explorer's txid-inclusion scope (intentional,
documented); UI colour/wording per consumer (presentation); `validate.js` non-deterministic
count (documented; fuzzer by design).

## Final question

> Given only the frozen specification, could another competent developer implement
> `headers-node` and know the result for every important adversarial case?

**Cryptographic inclusion result: YES** — §C/§D/§E plus the corpus fully determine cases
1–5, 7–10, 13–14 at the cryptographic level. **Full semantic result: NO** — cases 6
(POLICY-REJECTED vs FAILED), 11 (INDETERMINATE), and the evidence digest (B4) are specified as
*targets* but not yet realised, so two implementations built today would agree on the crypto and
disagree on the outcome label and the digest. Closing B1–B5 (implementation) and finalizing the
digest byte-framing flips this to YES. None requires new verification capability; each is a
bounded labeling/representation change to be done as its own pass, deliberately **not** in this
review.
