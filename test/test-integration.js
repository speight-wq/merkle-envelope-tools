'use strict';
const fs = require('fs');
const vm = require('vm');
const crypto = require('crypto');
const BUMP = require('./bump.js');
const BEEF = require('./beef.js');

// --- extract the inline IIFE from the wired verifier.html --------------------
const html = fs.readFileSync('./verifier.html', 'utf8');
const start = html.indexOf('(function() {');
const end = html.indexOf('})();', start) + '})();'.length;
const script = html.slice(start, end);

// --- build a genuine BUMP envelope from validated vector data ----------------
const parsed = BEEF.parse(BEEF.VECTOR.hex);
const bump = parsed.bumps[0];
const tx0 = parsed.transactions[0];
const displayRoot = BUMP.merkleRoot(bump, tx0.txid);
const naturalRoot = displayRoot.match(/../g).reverse().join('');
const header = '01000000' + '00'.repeat(32) + naturalRoot + '00000000' + '00000000' + '00000000';
if (header.length !== 160) throw new Error('constructed header wrong length');

const goodEnvelope    = { txid: tx0.txid, rawTx: tx0.rawHex, blockHeader: header, bump: BUMP.toHex(bump) };
const tamperedHeader  = '01000000' + '00'.repeat(32) + ('ff' + naturalRoot.slice(2)) + '00000000'.repeat(3);
const badEnvelope     = { txid: tx0.txid, rawTx: tx0.rawHex, blockHeader: tamperedHeader, bump: BUMP.toHex(bump) };
const legacyEnvelope  = { txid: tx0.txid, rawTx: tx0.rawHex, blockHeader: header, proof: [{ hash: '00'.repeat(32), pos: 'left' }] };

// --- stub the lib/ functions the surrounding code calls ----------------------
function hash256(hex) {
  const b = Buffer.from(hex, 'hex');
  return crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest();
}
const stubs = {
  hash256,
  bytesToHex: (buf) => Buffer.from(buf).toString('hex'),
  reverseHex: (hex) => hex.match(/../g).reverse().join(''),
  parseHeader: () => ({ timestamp: 0, merkleRoot: 'stub' }),
  verifyPoW: () => true,
  hashHeader: () => '00'.repeat(32),
  checkMerkleProofSafe: () => true,
  verifyMerkleProof: () => true,
  // Production-scope bindings the wired verifier now calls (headers.js globals in the
  // browser). These envelopes use constructed headers and this suite tests proof/root/
  // txid behaviour, not difficulty — so difficulty is stubbed true, consistent with the
  // existing verifyPoW stub. No chain is loaded here, so chain inclusion is 'unknown'.
  validateHeaderDifficulty: () => ({ valid: true }),
  chainInclusion: () => ({ status: 'unknown' }),
  BUMP, BEEF, Date, console
};

function makeDoc() {
  const els = {};
  const el = (id) => (els[id] || (els[id] = {
    _tc: '', _html: '', _cn: '', _v: '',
    addEventListener(ev, fn) { this._click = fn; },
    classList: { add() {}, remove() {} },
    get value() { return this._v; }, set value(x) { this._v = x; },
    set textContent(x) { this._tc = x; }, set className(x) { this._cn = x; }, set innerHTML(x) { this._html = x; }
  }));
  return { document: { getElementById: el }, els };
}

function run(envelope) {
  const { document, els } = makeDoc();
  const ctx = Object.assign({ document }, stubs);
  vm.createContext(ctx);
  vm.runInContext(script, ctx);
  ctx.document.getElementById('envelope-input').value = JSON.stringify(envelope);
  ['result-box', 'result-title', 'checks', 'details', 'result-section'].forEach(id => ctx.document.getElementById(id));
  ctx.document.getElementById('verify-btn')._click();
  return { title: els['result-title']._tc, checks: (els['checks']._html || '').replace(/<[^>]+>/g, ' ') };
}

// --- assertions --------------------------------------------------------------
let pass = 0, fail = 0;
const say = (c, m) => { c ? pass++ : fail++; console.log((c ? 'PASS ' : 'FAIL ') + m); };

const good = run(goodEnvelope);
say(/VALID PROOF — INCLUSION NOT PROVEN/.test(good.title), 'valid BUMP envelope -> VALID PROOF, inclusion not proven (isolation; no chain loaded)');
say(/BUMP Merkle root matches block header/.test(good.checks), 'valid BUMP envelope -> matching-root check present');
say(/TXID matches rawTx hash/.test(good.checks), 'txid/rawTx check still runs');

const bad = run(badEnvelope);
say(/VERIFICATION FAILED/.test(bad.title), 'tampered header -> FAILED');
say(/does not match header/.test(bad.checks), 'tampered header -> mismatch reported');

const legacy = run(legacyEnvelope);
say(/Merkle proof valid/.test(legacy.checks), 'legacy proof path still works (unchanged)');

console.log('\n----------------------------------------');
console.log(`PASSED: ${pass}   FAILED: ${fail}`);
process.exit(fail ? 1 : 0);
