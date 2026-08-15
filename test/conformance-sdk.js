/*
 * conformance-sdk.js — the one check that must run on YOUR machine, not in the
 * assistant's sandbox: byte-for-byte agreement with the reference @bsv/sdk.
 *
 * The in-container validate.js proved bump.js/beef.js against an independent
 * Merkle oracle across many shapes. This proves the remaining thing that matters
 * for ecosystem interop: that what your modules emit/parse is bit-identical to
 * what @bsv/sdk emits/parses, so a proof from any BRC-100 wallet round-trips.
 *
 * SETUP:
 *   npm init -y
 *   npm install @bsv/sdk
 *   node conformance-sdk.js
 *
 * The two seed vectors are the published BRC-74 / BRC-62 examples. The real value
 * comes from ADDING vectors captured from your own SDK usage or the ts-sdk test
 * fixtures (search the @bsv/sdk repo for MerklePath / BEEF fixture hex) into the
 * arrays below — the more real-world shapes, the stronger the guarantee.
 */
'use strict';

let sdk;
try { sdk = require('@bsv/sdk'); }
catch (e) { console.error('Install the SDK first:  npm install @bsv/sdk'); process.exit(2); }

const { MerklePath, Transaction } = sdk;
const BUMP = require('./bump.js');
const BEEF = require('./beef.js');

let pass = 0, fail = 0;
const fails = [];
const ok = (c, m) => { if (c) pass++; else { fail++; fails.push(m); } };

// ---------------------------------------------------------------------------
// BUMP vectors: [hex, [client txids to check]]
// ---------------------------------------------------------------------------
const BUMP_VECTORS = [
  [BUMP.VECTOR.hex, BUMP.VECTOR.txids],
  // ADD MORE: e.g. paste MerklePath hex from your wallet or the ts-sdk fixtures.
];

for (let v = 0; v < BUMP_VECTORS.length; v++) {
  const [hex, txids] = BUMP_VECTORS[v];
  try {
    const sdkMP = MerklePath.fromHex(hex);
    const mine = BUMP.fromHex(hex);

    // 1. serialization is byte-identical
    ok(BUMP.toHex(mine).toLowerCase() === sdkMP.toHex().toLowerCase(),
      `BUMP[${v}] toHex matches @bsv/sdk`);

    // 2. computed roots agree, per client txid
    for (const txid of txids) {
      const sdkRoot = sdkMP.computeRoot(txid);
      const myRoot = BUMP.merkleRoot(mine, txid);
      ok(myRoot === sdkRoot, `BUMP[${v}] root for ${txid.slice(0, 12)}… (mine ${myRoot.slice(0,12)}… / sdk ${String(sdkRoot).slice(0,12)}…)`);
    }
  } catch (e) { fail++; fails.push(`BUMP[${v}] threw: ${e.message}`); }
}

// ---------------------------------------------------------------------------
// BEEF vectors: [hex]
// ---------------------------------------------------------------------------
const BEEF_VECTORS = [
  BEEF.VECTOR.hex,
  // ADD MORE: capture tx.toBEEF() hex from your own SDK flows and paste here.
];

for (let v = 0; v < BEEF_VECTORS.length; v++) {
  const hex = BEEF_VECTORS[v];
  try {
    const mine = BEEF.parse(hex);

    // 1. @bsv/sdk parses the same bytes into a transaction with the same id
    const sdkTx = Transaction.fromHexBEEF ? Transaction.fromHexBEEF(hex)
                 : Transaction.fromBEEF(hexToBytes(hex));
    const sdkSubjectId = sdkTx.id('hex');
    const mineSubjectId = mine.transactions[mine.transactions.length - 1].txid;
    ok(sdkSubjectId === mineSubjectId, `BEEF[${v}] subject txid agrees (mine ${mineSubjectId.slice(0,12)}… / sdk ${sdkSubjectId.slice(0,12)}…)`);

    // 2. re-emitting via @bsv/sdk yields bytes my parser round-trips identically
    const sdkBeefHex = bytesToHex(sdkTx.toBEEF());
    ok(BEEF.build(BEEF.parse(sdkBeefHex)) === sdkBeefHex.toLowerCase(),
      `BEEF[${v}] my parser round-trips the SDK's own BEEF output`);
  } catch (e) { fail++; fails.push(`BEEF[${v}] threw: ${e.message}`); }
}

// ---------------------------------------------------------------------------
// Freshly-generated vector: build a proof with the SDK, verify with mine.
// (Requires a MerklePath the SDK builds; skipped gracefully if API differs.)
// ---------------------------------------------------------------------------
try {
  if (MerklePath && typeof MerklePath.fromHex === 'function') {
    // round-trip the seed through the SDK, then through mine, and compare roots
    const mp = MerklePath.fromHex(BUMP.VECTOR.hex);
    const reHex = mp.toHex();
    for (const txid of BUMP.VECTOR.txids) {
      ok(BUMP.merkleRoot(BUMP.fromHex(reHex), txid) === mp.computeRoot(txid),
        `cross: mine matches SDK after SDK re-serialization (${txid.slice(0,12)}…)`);
    }
  }
} catch (e) { fail++; fails.push('cross-gen threw: ' + e.message); }

// ---------------------------------------------------------------------------
function hexToBytes(h) { const a = []; for (let i = 0; i < h.length; i += 2) a.push(parseInt(h.substr(i, 2), 16)); return a; }
function bytesToHex(a) { return a.map(b => (b < 16 ? '0' : '') + (b & 0xff).toString(16)).join(''); }

console.log('----------------------------------------');
console.log(`@bsv/sdk conformance —  PASSED: ${pass}   FAILED: ${fail}`);
if (fail) { console.log('\nFAILURES:'); fails.forEach(f => console.log('  - ' + f)); }
console.log('\nAdd your own captured BUMP/BEEF hex to the vector arrays above for a stronger guarantee.');
process.exit(fail ? 1 : 0);
