/*
 * test-audit-fixes.js — regression tests for the audit fixes (items 1,2,9).
 * Run: node test/test-audit-fixes.js   (from the repo root)
 *
 * Deterministic logic tests only — no forged-PoW headers required. Exercises:
 *   - checkpoint anchor enforcement (FP-1)
 *   - raise-only dynamic floor (FP-2)
 *   - BUMP/BEEF Reader bounds + strict hex + consume-all (item 9)
 *   - verifyMined contract (items 7/9)
 */
'use strict';
require('../lib/crypto.js');
require('../lib/encoding.js');
require('../lib/headers.js');
const BUMP = require('../lib/bump.js');
const BEEF = require('../lib/beef.js');

let pass = 0, fail = 0;
function check(name, cond) { (cond ? pass++ : fail++); console.log((cond ? 'PASS ' : 'FAIL ') + name); }
function throws(name, fn, match) {
  try { fn(); check(name + ' (expected throw)', false); }
  catch (e) { check(name, match ? new RegExp(match, 'i').test(e.message) : true); }
}

const CP = global.CHECKPOINT;

// Build a minimal headers.bin buffer header: [height u32][anchorHash 32][count u32] + headers*80
function buildChainFile(anchorHeight, anchorHashHex, headerHexes) {
  const head = new Uint8Array(40 + headerHexes.length * 80);
  const dv = new DataView(head.buffer);
  dv.setUint32(0, anchorHeight, true);
  head.set(global.hexToBytes(anchorHashHex), 4);
  dv.setUint32(36, headerHexes.length, true);
  let off = 40;
  for (const h of headerHexes) { head.set(global.hexToBytes(h), off); off += 80; }
  return head;
}

// ---- Item 1: checkpoint anchor enforcement -----------------------------------
// Fabricated anchor (wrong hash), zero headers -> must throw on the anchor check.
const fakeAnchor = '00'.repeat(32);
throws('FP-1: fabricated anchor rejected by default',
  () => global.verifyHeaderChain(buildChainFile(CP.height, fakeAnchor, []), CP),
  'checkpoint');

// Wrong height, real hash -> still rejected.
throws('FP-1: wrong anchor height rejected',
  () => global.verifyHeaderChain(buildChainFile(CP.height + 5, CP.hash, []), CP),
  'checkpoint');

// Correct anchor, zero headers -> passes anchor check (no throw), tip == anchor.
(function () {
  const res = global.verifyHeaderChain(buildChainFile(CP.height, CP.hash, []), CP);
  check('FP-1: genuine checkpoint anchor accepted', res.checkpointVerified === true && res.tipHeight === CP.height);
})();

// Explicit opt-out still allowed for the weaker mode.
(function () {
  const res = global.verifyHeaderChain(buildChainFile(CP.height, fakeAnchor, []), CP, { requireCheckpoint: false });
  check('FP-1: requireCheckpoint:false opts into weak mode', res.checkpointVerified === false);
})();

// ---- Item 2: raise-only dynamic floor ----------------------------------------
(function () {
  const staticFloor = global.STATIC_FLOOR_TARGET;
  // Simulate a forged easy tip: a huge target (very low difficulty).
  const easyTarget = staticFloor * 1000n;
  // setDynamicFloor stores targetFromNBits(nBits)*8; emulate by directly probing
  // getEffectiveFloor after a dynamic set that would be MORE permissive.
  global.setDynamicFloor(0x1d00ffff, 999999); // difficulty-1-ish nBits -> very large target
  const eff = global.getEffectiveFloor();
  check('FP-2: dynamic floor cannot exceed static floor (raise-only)',
    eff.target <= staticFloor);
  global.clearDynamicFloor();
  const eff2 = global.getEffectiveFloor();
  check('FP-2: floor reverts to static after clear', eff2.target === staticFloor);
})();

// ---- Item 9: BUMP/BEEF strictness --------------------------------------------
throws('item9: BUMP rejects trailing garbage',
  () => BUMP.fromHex(BUMP.VECTOR.hex + 'deadbeef'), 'trailing');
throws('item9: BUMP rejects truncated stream',
  () => BUMP.fromHex(BUMP.VECTOR.hex.slice(0, BUMP.VECTOR.hex.length - 20)), 'end of stream|read past');
throws('item9: BUMP rejects non-hex',
  () => BUMP.fromHex('zz' + BUMP.VECTOR.hex.slice(2)), 'invalid hex');
check('item9: BUMP still parses the valid vector', (function () {
  const b = BUMP.fromHex(BUMP.VECTOR.hex); return BUMP.merkleRoot(b, BUMP.VECTOR.txids[0]) === BUMP.VECTOR.root;
})());

throws('item9: BEEF rejects trailing garbage',
  () => BEEF.parse(BEEF.VECTOR.hex + 'dead'), 'trailing|end of stream');
throws('item9: verifyMined requires a root callback',
  () => BEEF.verifyMined(BEEF.parse(BEEF.VECTOR.hex)), 'callback');
(function () {
  const beef = BEEF.parse(BEEF.VECTOR.hex);
  const rep = BEEF.verifyMined(beef, () => true);
  // Vector has 1 proven + 1 unproven -> allProvenValid must now be false.
  check('item9: allProvenValid false when an unproven tx is present', rep.allProvenValid === false);
  const rep2 = BEEF.verifyMined(beef, BEEF.verifyMined.UNSAFE_SKIP_ROOT_CHECK);
  check('item9: UNSAFE sentinel still computes (proven=1)', rep2.proven.length === 1);
})();

console.log('\n' + (fail === 0 ? 'ALL PASSED' : fail + ' FAILURE(S)') + ' (' + pass + ' passed)');
process.exit(fail === 0 ? 0 : 1);
