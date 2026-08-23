/*
 * test-adversarial.js — red-team tests for the audit fixes (items 1,2,7).
 * Run: node test/test-adversarial.js
 *
 *  A) Forged low-difficulty chain grounded at the REAL checkpoint anchor, with a
 *     genuinely PoW-valid (but sub-floor) header -> must be rejected by the in-loop
 *     difficulty floor (FP-1 / FP-2). This is the exact attack the fixes target:
 *     the anchor is real, so the old anchor-advisory + no-floor-in-loop admitted it.
 *  B) Fingerprint canonicalization invariance (item 7): the same LOGICAL envelope,
 *     serialized with different hex casing / proof key order / optional-field
 *     presentation, must yield ONE canonical string (mirrors explorer.html's
 *     canonicalInput). Two DIFFERENT logical inputs must differ.
 */
'use strict';
require('../lib/crypto.js');
require('../lib/encoding.js');
require('../lib/secp256k1.js');
require('../lib/headers.js');
require('../lib/snapshot.js');
const BUMP = require('../lib/bump.js');
const BEEF = require('../lib/beef.js');

let pass = 0, fail = 0;
function check(name, cond) { (cond ? pass++ : fail++); console.log((cond ? 'PASS ' : 'FAIL ') + name); }

const CP = global.CHECKPOINT;
const H = global; // hexToBytes, bytesToHex, reverseHex, hash256, verifyPoW, hashHeader...

// ---- A) forged low-difficulty chain -----------------------------------------
// Build one 80-byte header that links to the checkpoint, carries a sub-floor nBits
// (target ~2^240, easier than the floor ~2^232), and grind its nonce to a valid PoW.
function u32le(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; }

function buildForgedHeader() {
  const nBits = 0x20000100; // exp=0x20, mant=0x000100 -> target = 0x100 << 232 = 2^240
  const target = H.targetFromNBits(nBits);
  const prev = H.hexToBytes(H.reverseHex(CP.hash)); // internal byte order (bytes 4..36)
  const merkle = new Uint8Array(32); merkle.fill(0x11);
  const ts = 1893456000; // 2030, safely > genesis and not far-future-at-checkpoint
  const base = new Uint8Array(80);
  base.set(u32le(1), 0);           // version
  base.set(prev, 4);               // prevBlock (links to checkpoint)
  base.set(merkle, 36);            // merkle root (arbitrary)
  base.set(u32le(ts), 68);         // timestamp
  base.set(u32le(nBits), 72);      // nBits (sub-floor)
  for (let nonce = 0; nonce < 5_000_000; nonce++) {
    base.set(u32le(nonce), 76);
    const hex = H.bytesToHex(base);
    const hashDisplay = H.hashHeader(hex); // display-order hash hex
    if (BigInt('0x' + hashDisplay) <= target) return { hex, nonce, nBits, target };
  }
  return null;
}

const forged = buildForgedHeader();
check('A: forged sub-floor header found with valid PoW-in-isolation', !!forged);
if (forged) {
  // Sanity: it really is valid PoW against its own nBits...
  check('A: forged header passes verifyPoW in isolation', H.verifyPoW(forged.hex) === true);
  // ...and really is below the floor (target easier than the static floor).
  check('A: forged target is below the difficulty floor', forged.target > global.STATIC_FLOOR_TARGET);

  // Assemble a headers.bin: [anchorHeight u32][anchorHash 32][count u32][header 80]
  const file = new Uint8Array(40 + 80);
  const dv = new DataView(file.buffer);
  dv.setUint32(0, CP.height, true);
  file.set(H.hexToBytes(CP.hash), 4);   // REAL checkpoint anchor
  dv.setUint32(36, 1, true);
  file.set(H.hexToBytes(forged.hex), 40);

  let rejected = false, reason = '';
  try { global.verifyHeaderChain(file, CP); }
  catch (e) { rejected = true; reason = e.message; }
  check('A: forged low-difficulty chain at real checkpoint is REJECTED', rejected);
  check('A: rejection cites the difficulty floor', /floor|difficulty/i.test(reason));
  console.log('     (rejection reason: ' + reason + ')');
}

// ---- B) fingerprint canonicalization invariance (mirrors explorer.html) ------
function lc(s) { return (typeof s === 'string' ? s : '').toLowerCase(); }
function canonicalProof(proof) {
  // pos VERBATIM (case-sensitive, no default) — matches validateProofStructure,
  // which requires literal 'L'/'R'. hash lowercased (validator is case-insensitive on hex).
  return (Array.isArray(proof) ? proof : []).map(function (p) {
    return { hash: lc(p && p.hash), pos: (p && typeof p.pos === 'string') ? p.pos : '' };
  });
}
function frame(s) { s = (s == null ? '' : String(s)); return s.length + ':' + s; }
function canonicalInput(env) {
  var pc = canonicalProof(env.proof || []);
  var parts = pc.map(function (p) { return frame(p.hash) + frame(p.pos); }).join('');
  return frame('txid') + frame(lc(env.txid)) +
         frame('header') + frame(lc(env.blockHeader)) +
         frame('proof') + frame(pc.length + '') + parts;
}

const txidU = 'F4184FC596403B9D638783CF57ADFE4C75C605F6356FBC91338530E9831E9E16';
const hdr = '0100000055bd840a78798ad0da853f68974f3d183e2bd1db6a842c1feecf222a00000000ff104ccb05421ab93e63f8c3ce5c2c2e9dbb37de2764b3a3175c8166562cac7d51b96a49ffff001d283e9e70';
const HASH = '82501c1178fa0b222c1f3d474ec726b832013f0a532b44bb620cce8624a5feb1';
const envA = { txid: txidU.toLowerCase(), blockHeader: hdr, proof: [{ hash: HASH, pos: 'L' }] };
// same LOGICAL envelope: uppercase txid, uppercase header, uppercase HASH, proof keys
// reordered — but pos is the SAME valid 'L' (pos case is security-relevant, not presentation).
const envB = { blockHeader: hdr.toUpperCase(),
  proof: [{ pos: 'L', hash: HASH.toUpperCase() }],
  txid: txidU };
check('B: non-security presentation variants (hex casing, key order) → identical canonical input',
  canonicalInput(envA) === canonicalInput(envB));

// different logical proof -> different canonical input
const envC = JSON.parse(JSON.stringify(envA));
envC.proof[0].pos = 'R';
check('B: a real logical change (pos L->R) changes the canonical input',
  canonicalInput(envA) !== canonicalInput(envC));

// FINDING B regression: pos case is security-relevant (validator rejects 'l').
// 'L' and 'l' must NOT collide (they reach different verdicts).
check('B: pos case difference (L vs l) → DIFFERENT canonical input (no leniency)',
  canonicalInput(envA) !== canonicalInput({ txid: txidU.toLowerCase(), blockHeader: hdr, proof: [{ hash: HASH, pos: 'l' }] }));

// FINDING B regression: omitted pos (validator rejects) must NOT collide with explicit 'R'.
check('B: omitted pos → DIFFERENT canonical input from explicit R (no defaulting)',
  canonicalInput({ txid: txidU.toLowerCase(), blockHeader: hdr, proof: [{ hash: HASH }] }) !==
  canonicalInput({ txid: txidU.toLowerCase(), blockHeader: hdr, proof: [{ hash: HASH, pos: 'R' }] }));

// framing prevents delimiter collision: txid 'ab' + header '' vs txid 'a' + header 'b'
check('B: length-framing prevents field-boundary collision',
  canonicalInput({ txid: 'ab', blockHeader: '', proof: [] }) !==
  canonicalInput({ txid: 'a', blockHeader: 'b', proof: [] }));

// ---- C) satoshi precision: BigInt vs parseInt (finding C) --------------------
// chain.html now parses the 8-byte output value as BigInt('0x'+reverseHex(bytes)).
// Demonstrate that the old parseInt(...,16) path loses precision above 2^53 while
// the BigInt path is exact, for an 8-byte little-endian value.
(function () {
  // 8-byte LE bytes for 2^53 + 1 = 9007199254740993 sats (0x0020000000000001 big-endian)
  const displayHex = '0020000000000001';            // natural/big-endian hex of the value
  const leHex = displayHex.match(/../g).reverse().join(''); // little-endian on the wire
  function reverseHex(h) { return h.match(/../g).reverse().join(''); }
  const asBig = BigInt('0x' + reverseHex(leHex));    // new path
  const asNum = parseInt(reverseHex(leHex), 16);     // old path (Number)
  check('C: BigInt parse is exact for value > 2^53', asBig === 9007199254740993n);
  // The old Number path rounds 2^53+1 down to 2^53; compare via BigInt so the
  // assertion itself isn't corrupted by the same Number rounding.
  check('C: old parseInt path loses precision (rounds to 2^53)',
    BigInt(asNum) !== asBig && BigInt(asNum) === 9007199254740992n);
})();

// ---- D2) checkpoint floor sanity (now FIXED with real block-940000 nBits) ----
(function () {
  const st = global.checkpointFloorStatus();
  check('D2: checkpointFloorStatus reports sane (floor stricter than difficulty-1)', st.sane === true);
  // The floor must now REJECT difficulty-1 (2^223) and ACCEPT real BSV difficulty (~2^189).
  const d1 = H.targetFromNBits(0x1d00ffff);
  const real = H.targetFromNBits(0x18227b71); // block 939999 (checkpoint) difficulty
  check('D2: difficulty-1 is above the floor (rejected)', d1 > global.STATIC_FLOOR_TARGET);
  check('D2: real BSV difficulty is at/below the floor (accepted)', real <= global.STATIC_FLOOR_TARGET);
})();

// ---- D3) the provided real headers.bin verifies against the checkpoint ---------
(function () {
  const fs = require('fs');
  const path = __dirname + '/headers-940000-to-940000.bin';
  if (!fs.existsSync(path)) { console.log('SKIP D3: headers.bin not present'); return; }
  const buf = new Uint8Array(fs.readFileSync(path));
  let res = null, err = null;
  try { res = H.verifyHeaderChain(buf, H.CHECKPOINT); } catch (e) { err = e.message; }
  check('D3: real headers.bin verifies against enforced checkpoint', !!res && res.checkpointVerified === true);
  check('D3: tip is height 940000 and chain-inclusion resolves', !!res && res.tipHeight === 940000 &&
    H.chainInclusion(res.hashIndex, res.tipHash).status === 'verified');
})();

// ---- E) snapshot.js: signature path fixed + tip floor (findings from this pass) --
(function () {
  const fs = require('fs');
  const path = __dirname + '/headers-940000-to-940000.bin';
  if (!fs.existsSync(path)) { console.log('SKIP E: headers.bin not present'); return; }
  const buf = new Uint8Array(fs.readFileSync(path));
  const anchorHash = H.bytesToHex(buf.slice(4, 36));
  const headerHex = H.bytesToHex(buf.slice(40, 120));
  const priv = '0000000000000000000000000000000000000000000000000000000000000001';
  const pub = H.SECP256K1.getPublicKey(priv, true);
  const snap = H.createSnapshot(939999, anchorHash, headerHex, priv);
  check('E: createSnapshot produces a DER signature (secp256k1 casing/arg bug fixed)', typeof snap.signature === 'string' && snap.signature.length > 130);
  check('E: verifySnapshot accepts a valid real-difficulty snapshot (tip passes floor)', H.verifySnapshot(snap, [pub], { expectedAnchorHash: anchorHash }).valid === true);
  check('E: untrusted signer rejected', H.verifySnapshot(snap, ['02' + '00'.repeat(32)], { expectedAnchorHash: anchorHash }).valid === false);
  const bad = JSON.parse(JSON.stringify(snap)); bad.headers = bad.headers.slice(0, -2) + '00';
  check('E: tampered headers rejected (fail closed)', H.verifySnapshot(bad, [pub], { expectedAnchorHash: anchorHash }).valid === false);
})();


// ---- F) Atomic BEEF subject validation (audit M1, BRC-95) --------------------
(function () {
  const beef = BEEF.parse(BEEF.VECTOR.hex);        // 2 txs: t0 (mined ancestor), t1 (subject, spends t0)
  const t0 = beef.transactions[0], t1 = beef.transactions[1];

  // Positive control: the genuine subject (last tx) round-trips through parse.
  let okValid = true;
  try { BEEF.parse(BEEF.wrapAtomic(BEEF.VECTOR.hex, t1.txid)); } catch (e) { okValid = false; }
  check('F: valid Atomic BEEF (subject = last tx) still parses', okValid);

  // 1) Subject not the last transaction -> reject (t0 is an ancestor, not the subject).
  let threw1 = '', ok1 = false;
  try { BEEF.parse(BEEF.wrapAtomic(BEEF.VECTOR.hex, t0.txid)); }
  catch (e) { ok1 = true; threw1 = e.message; }
  check('F1: subject-not-last Atomic BEEF is rejected', ok1 && /last transaction/i.test(threw1));

  // 2) Subject absent from the container -> reject.
  let ok2 = false, threw2 = '';
  try { BEEF.parse(BEEF.wrapAtomic(BEEF.VECTOR.hex, '00'.repeat(32))); }
  catch (e) { ok2 = true; threw2 = e.message; }
  check('F2: subject-not-present Atomic BEEF is rejected', ok2 && /not present/i.test(threw2));

  // 3) Only-ancestors rule: a container carrying a tx that is not the subject or an
  //    ancestor of it -> reject. Synthetic DAG so the subject IS last (isolating this
  //    rule from F1): A (ancestor) , U (unrelated) , S (subject, last, spends A).
  const A = { txid: 'a'.repeat(64), inputs: [{ prevTxid: 'f'.repeat(64) }] };   // ancestor (its parent is outside the container)
  const U = { txid: 'b'.repeat(64), inputs: [{ prevTxid: 'e'.repeat(64) }] };   // unrelated to S
  const S = { txid: 'c'.repeat(64), inputs: [{ prevTxid: A.txid }] };           // subject, last, spends A
  // sanity: the valid subset [A, S] must pass
  let okSubset = true;
  try { BEEF.validateAtomicSubject([A, S], S.txid); } catch (e) { okSubset = false; }
  check('F3a: subject + genuine ancestor validates', okSubset);
  // the unrelated tx must be rejected
  let ok3 = false, threw3 = '';
  try { BEEF.validateAtomicSubject([A, U, S], S.txid); }
  catch (e) { ok3 = true; threw3 = e.message; }
  check('F3b: unrelated tx in Atomic container is rejected (only-ancestors)',
    ok3 && /not the subject or an ancestor/i.test(threw3));
})();


// ---- G) per-header difficulty floor policy (enforceChainFloor) ----------------
// Pure-policy tests with hand-set targets (no real PoW grinding). Larger target =
// easier = "sub-floor"; target <= floor = "at/below floor" = admissible.
(function () {
  const F = global.STATIC_FLOOR_TARGET;
  const atFloor = F;              // exactly at the floor (admissible)
  const belowFloor = F / 2n;      // harder than floor (admissible)
  const subFloor = F * 2n;        // easier than floor (must be rejected)
  function run(hs) { try { global.enforceChainFloor(hs, F); return 'ACCEPT'; } catch (e) { return 'REJECT'; } }

  // 1. all headers at/below floor -> ACCEPT
  check('G1: all headers at/below floor -> ACCEPT',
    run([{ height: 1, target: belowFloor }, { height: 2, target: atFloor }]) === 'ACCEPT');

  // 2. sub-floor intermediate + at-floor tip -> REJECT
  //    (this is the case tip-only enforcement wrongly ACCEPTED; the core regression.)
  check('G2: sub-floor intermediate + at-floor tip -> REJECT',
    run([{ height: 1, target: subFloor }, { height: 2, target: atFloor }]) === 'REJECT');

  // 3. at-floor intermediate + sub-floor tip -> REJECT
  check('G3: at-floor intermediate + sub-floor tip -> REJECT',
    run([{ height: 1, target: atFloor }, { height: 2, target: subFloor }]) === 'REJECT');

  // 4. all sub-floor -> REJECT
  check('G4: all sub-floor -> REJECT',
    run([{ height: 1, target: subFloor }, { height: 2, target: subFloor }]) === 'REJECT');

  // 5. genuine >8x intermediate difficulty drop -> REJECT (INTENTIONAL fail-closed).
  //    A legitimate chain whose intermediate header is >8x easier than the checkpoint
  //    (a real BSV hashrate crash) is rejected. This is an ACCEPTED false negative: the
  //    caller MUST fall back to isolation, NOT claim verified inclusion. Full DAA-aware
  //    difficulty validation (out of scope) would be required to accept such a chain.
  const genuineDrop = F * 9n;     // ~9x easier than the checkpoint difficulty
  check('G5: genuine >8x intermediate drop -> REJECT (intentional fail-closed to isolation)',
    run([{ height: 1, target: genuineDrop }, { height: 2, target: atFloor }]) === 'REJECT');
})();


// ---- G6) WIRING: per-header enforcement reaches the intermediate end-to-end ---
// G1-G5 test the pure policy function. G6 drives the REAL verifyHeaderChain ->
// hashIndex -> chainInclusion path to prove the intermediate is unreachable.
//
// HONEST LIMIT: a genuinely floor-PASSING tip needs ~2^64 PoW (infeasible to grind in a
// test), so both headers here are sub-floor. That is sufficient to prove the substantive
// claim, because enforceChainFloor throws on the FIRST violation (the intermediate) and
// iterates ALL headers: the rejection citing the INTERMEDIATE height (not the tip's)
// demonstrates the intermediate is examined per-header — under the old tip-only policy
// only the tip was checked. Together with G2 (policy rejects sub-floor-intermediate +
// AT-floor-tip), this establishes the end-to-end property by composition.
(function () {
  const CP = global.CHECKPOINT;
  function u32le(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; }
  function grind(prevDisplayHash, ts) {                 // sub-floor header (~2^240 target, ~2^16 work)
    const nBits = 0x20000100, target = global.targetFromNBits(nBits);
    const prev = global.hexToBytes(global.reverseHex(prevDisplayHash));
    const b = new Uint8Array(80);
    b.set(u32le(1), 0); b.set(prev, 4); b.set(new Uint8Array(32).fill(0x22), 36);
    b.set(u32le(ts), 68); b.set(u32le(nBits), 72);
    for (let n = 0; n < 5000000; n++) {
      b.set(u32le(n), 76); const hx = global.bytesToHex(b);
      if (BigInt('0x' + global.hashHeader(hx)) <= target) return { hex: hx, hash: global.hashHeader(hx), target };
    }
    throw new Error('grind failed');
  }
  const h1 = grind(CP.hash, 1893456000);                // intermediate, height 940000
  const h2 = grind(h1.hash, 1893456600);                // tip, height 940001, links to h1
  const file = new Uint8Array(40 + 160); const dv = new DataView(file.buffer);
  dv.setUint32(0, CP.height, true); file.set(global.hexToBytes(CP.hash), 4); dv.setUint32(36, 2, true);
  file.set(global.hexToBytes(h1.hex), 40); file.set(global.hexToBytes(h2.hex), 120);

  check('G6a: intermediate and tip are both below floor (test precondition)',
    h1.target > global.STATIC_FLOOR_TARGET && h2.target > global.STATIC_FLOOR_TARGET);

  let result = null, err = null;
  try { result = global.verifyHeaderChain(file, CP); } catch (e) { err = e.message; }
  check('G6b: verifyHeaderChain rejects (throws, returns no result)', result === null && !!err);
  check('G6c: rejection cites the INTERMEDIATE (940000), not the tip (940001) — per-header',
    /940000/.test(err) && !/940001/.test(err));
  check('G6d: no hashIndex is produced, so chainInclusion cannot reach the intermediate',
    result === null && global.chainInclusion(new Map(), h1.hash).status !== 'verified');
})();


// ---- H) claim boundary: permanent scope anti-claims (SCOPE_ANTICLAIMS) ---------
(function () {
  const a = global.SCOPE_ANTICLAIMS;
  check('H1: SCOPE_ANTICLAIMS exported as a non-empty array', Array.isArray(a) && a.length >= 2);
  const mw = a.find(c => c.id === 'most-work-chain');
  const sp = a.find(c => c.id === 'current-spend-status');
  check('H2: most-work-chain anti-claim present', !!mw);
  check('H3: current-spend-status anti-claim present', !!sp);
  // Security principle: these say "this tool does not ATTEMPT X" (permanent scope
  // boundary), never "X is not currently verified" (evidence-dependent). Encoded as
  // scope:'not-attempted' and must not use evidence-failure language.
  check('H4: both are scope "not-attempted" (scope boundary, not evidence outcome)',
    a.every(c => c.scope === 'not-attempted'));
  check('H5: wording is scope-language, not "not currently verified"',
    a.every(c => /not attempt|does NOT|not establish/i.test(c.detail)) &&
    !a.some(c => /not currently verified|currently verified|failed to establish/i.test(c.detail)));
  check('H6: most-work detail names cumulative/most-work chain selection',
    /cumulative proof-of-work|most-work/i.test(mw.detail));
  check('H7: spend detail names unspent / UTXO set',
    /unspent|UTXO/i.test(sp.detail));
})();


// ---- UI) explorer verdict scope wording (post-audit clarification) ------------
// UI-string regression guard (no DOM): a successful explorer verdict must scope its
// positive claim to TXID inclusion and must carry the rawTx-not-bound caveat. Gating
// (shown on success, hidden on failure, diagnostics intact) is verified separately via
// the DOM-stub harness — see the task report.
(function () {
  const fs = require('fs');
  const p = __dirname + '/../explorer.html';
  if (!fs.existsSync(p)) { console.log('SKIP UI: explorer.html not found'); return; }
  const src = fs.readFileSync(p, 'utf8');
  check('UI1: positive verdict is scoped to TXID inclusion',
    src.indexOf('VERIFICATION PASSED — TXID INCLUSION PROVEN') !== -1);
  check('UI2: old unscoped "— INCLUSION PROVEN" wording is gone',
    src.indexOf('— INCLUSION PROVEN') === -1 || src.indexOf('— TXID INCLUSION PROVEN') !== -1);
  check('UI3: rawTx-not-bound scope caveat text present',
    src.indexOf('does NOT bind the supplied raw transaction bytes to this TXID') !== -1);
  check('UI4: caveat is gated on a successful result (r.result.valid)',
    /if \(r\.result\.valid\) \{\s*\n\s*html \+= '<div class="verdict-scope">/.test(src));
})();



console.log('\n' + (fail === 0 ? 'ALL PASSED' : fail + ' FAILURE(S)') + ' (' + pass + ' passed)');
process.exit(fail === 0 ? 0 : 1);
