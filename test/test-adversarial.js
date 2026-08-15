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
require('../lib/headers.js');

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

// ---- D2) checkpoint floor sanity guard (real-data finding) -------------------
// The difficulty floor only has value if it is stricter than difficulty-1. Detect a
// misconfigured/placeholder checkpoint nBits that makes the floor toothless.
(function () {
  const st = global.checkpointFloorStatus();
  // With the SHIPPED checkpoint (0x1d2a0000) the floor is looser than difficulty-1,
  // so the guard must report NOT sane (this is the finding; flip to sane once the
  // real block-935000 nBits is set).
  check('D2: checkpointFloorStatus detects the toothless shipped floor', st.sane === false);
  check('D2: guard names the checkpoint and advises the fix', /checkpoint nBits|935000/i.test(st.reason));
})();


console.log('\n' + (fail === 0 ? 'ALL PASSED' : fail + ' FAILURE(S)') + ' (' + pass + ' passed)');
process.exit(fail === 0 ? 0 : 1);
