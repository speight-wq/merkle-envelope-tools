'use strict';
// Independent results, frozen BEFORE any differential vs reference/headers-node.
// Expected values come from the spec's frozen corpus (§ CONFORMANCE CONTRACT) and public
// standards, never from the reference implementation.
const fs = require('fs'), crypto = require('crypto');
const V = require('./verify.js');
const FIX = process.env.FIX || require('path').join(__dirname,'..');
const E = JSON.parse(fs.readFileSync(FIX + '/test/real-envelope.json', 'utf8'));
const clone = o => JSON.parse(JSON.stringify(o));
const strip = (o, k) => { const c = clone(o); delete c[k]; return c; };
const merge = (o, p) => Object.assign(clone(o), p);
const pad = (s, n) => { s = String(s); return s + ' '.repeat(Math.max(0, n - s.length)); };

const hdr = V.parseHeader(E.blockHeader);
const blockHash = V.headerHashDisplay(E.blockHeader);
const chainHas = new Map([[blockHash.toLowerCase(), 935023]]);
const chainLacks = new Map([['00'.repeat(32), 1]]);

// independent Bitcoin-Merkle oracle (built here) for constructing legacy-proof cases
const sd = b => crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest();
const toNat = h => Buffer.from(h, 'hex').reverse(), toDisp = b => Buffer.from(b).reverse().toString('hex');
function tree(txs) { let c = txs.map(toNat); const L = [c.slice()]; while (c.length > 1) { const n = []; for (let i = 0; i < c.length; i += 2) n.push(sd(Buffer.concat([c[i], (i + 1 < c.length) ? c[i + 1] : c[i]]))); L.push(n.slice()); c = n; } return { L, root: toDisp(L[L.length - 1][0]) }; }
function proofNat(t, idx) { const p = []; for (let h = 0; h < t.L.length - 1; h++) { const pos = idx >> h, s = pos ^ 1; const x = (s < t.L[h].length) ? t.L[h][s] : t.L[h][pos]; p.push({ hash: x.toString('hex'), pos: (pos & 1) ? 'L' : 'R' }); } return p; }

let pass = 0, fail = 0;
const rec = (ok) => { ok ? pass++ : fail++; return ok ? 'PASS' : 'FAIL'; };

// ---------- §5 CONFORMANCE CORPUS (frozen table) ----------
console.log('=== CONFORMANCE CORPUS (expected from spec frozen table) ===');
console.log(pad('Case', 34), pad('Spec expected', 20), pad('Independent', 20), 'Match');
const corpus = [
  ['1 valid inclusion', V.verify(E, { bindRawTx: true, chainHashIndex: chainHas, trustIndex: true }).outcome, 'VERIFIED'],
  ['2 valid isolation', V.verify(E, { bindRawTx: true }).outcome, 'VERIFIED-ISOLATION'],
  ['5 wrong header (root)', V.verify(merge(E, { blockHeader: (() => { const b = Buffer.from(E.blockHeader, 'hex'); b[36] ^= 0xff; return b.toString('hex'); })() }), { bindRawTx: true }).outcome, 'FAILED'],
  ['7 chain membership fail', V.verify(E, { bindRawTx: true, chainHashIndex: chainLacks, trustIndex: true }).outcome, 'FAILED'],
  ['8 malformed (bad hex)', V.verify(merge(E, { blockHeader: 'zz'.repeat(80) }), { bindRawTx: true }).outcome, 'MALFORMED'],
  ['9 missing header', V.verify(strip(E, 'blockHeader'), { bindRawTx: true }).outcome, 'MALFORMED'],
  ['9b empty header', V.verify(merge(E, { blockHeader: '' }), { bindRawTx: true }).outcome, 'MALFORMED'],
  ['4 wrong txid (bind)', V.verify(merge(E, { txid: 'ab'.repeat(32) }), { bindRawTx: true }).outcome, 'FAILED'],
  ['12 low-confirmations', V.verify(merge(E, { confirmations: 2 }), { bindRawTx: true }).outcome, 'VERIFIED-ISOLATION'],
];
for (const [name, got, exp] of corpus) console.log(pad(name, 34), pad(exp, 20), pad(got, 20), rec(got === exp));
// advisory presence for case 12
const adv = V.verify(merge(E, { confirmations: 2 }), { bindRawTx: true }).advisories.some(a => a.id === 'low-confirmations');
console.log(pad('12b low-confirm advisory flag', 34), pad('present', 20), pad(adv ? 'present' : 'absent', 20), rec(adv));

// ---------- legacy-proof cases (independent oracle) ----------
console.log('\n=== LEGACY PROOF (independent oracle, natural byte order §B) ===');
const txs = Array.from({ length: 9 }, () => crypto.randomBytes(32).toString('hex'));
const T = tree(txs); const idx = 3; const good = proofNat(T, idx);
// build a synthetic single-branch envelope whose header carries T.root — but PoW won't hold;
// so exercise rootFromLegacy directly (crypto invariant §C-2), expectations from the oracle.
const lp = [
  ['valid proof folds to root', V.rootFromLegacy(txs[idx], good) === T.root, true],
  ['wrong sibling', V.rootFromLegacy(txs[idx], good.map((s, i) => i === 0 ? { hash: 'ff' + s.hash.slice(2), pos: s.pos } : s)) === T.root, false],
  ['wrong txid', V.rootFromLegacy(crypto.randomBytes(32).toString('hex'), good) === T.root, false],
];
for (const [name, got, exp] of lp) console.log(pad(name, 34), pad(exp, 20), pad(got, 20), rec(got === exp));

// ---------- §6 ADVERSARIAL / CROSS-BINDING ----------
console.log('\n=== ADVERSARIAL (attack -> expected -> actual) ===');
const atk = [
  ['1 wrong txid', merge(E, { txid: 'ab'.repeat(32) }), { bindRawTx: false }, 'FAILED'],
  ['2 tampered sibling(bump)', merge(E, { bump: (() => { const b = Buffer.from(E.bump, 'hex'); b[b.length - 1] ^= 0xff; return b.toString('hex'); })() }), { bindRawTx: false }, 'FAILED'],
  ['3 tampered header root', merge(E, { blockHeader: (() => { const b = Buffer.from(E.blockHeader, 'hex'); b[40] ^= 0xff; return b.toString('hex'); })() }), { bindRawTx: false }, 'FAILED'],
  ['4 header absent from chain', E, { bindRawTx: false, chainHashIndex: chainLacks, trustIndex: true }, 'FAILED'],
  ['5 wrong rawTx', merge(E, { rawTx: '00' }), { bindRawTx: true }, 'FAILED'],
  ['6 contradictory legacy vs bump', merge(E, { proof: [{ hash: 'ff'.repeat(32), pos: 'L' }] }), { bindRawTx: false }, 'VERIFIED-ISOLATION'],
];
for (const [name, env, opts, exp] of atk) {
  const got = V.verify(env, opts).outcome;
  console.log(pad(name, 34), pad('->' + exp, 20), pad(got, 20), rec(got === exp) + (got !== 'VERIFIED' ? '' : '  <-- FALSE VERIFIED!'));
}

// ---------- §7 IDENTITY A / B / D ----------
console.log('\n=== IDENTITY INVARIANTS ===');
const base = { txid: 'ab'.repeat(32), blockHeader: '01'.repeat(80), proof: [{ hash: 'cd'.repeat(32), pos: 'L' }], rawTx: '00', bump: 'aa' };
const id = o => V.evidenceDigest(Object.assign({}, base, o));
const A = id({ bump: 'aa' }) !== id({ bump: 'bb' });
const Braw = id({ rawTx: undefined }) !== id({ rawTx: '' });
const Bbump = id({ bump: undefined }) !== id({ bump: '' });
const Bbeef = id({ beef: undefined }) !== id({ beef: '' });
const Batomic = id({ atomicBeef: undefined }) !== id({ atomicBeef: '' });
const D = id({ vout: 0, satoshis: 1, confirmations: 9, blockHash: 'z', blockHeight: 5 }) === id({ vout: 7, satoshis: 99, confirmations: 1, blockHash: 'q', blockHeight: 8 });
console.log(pad('A committed evidence changes id', 40), rec(A));
console.log(pad('B absent!=empty rawTx/bump/beef/atomic', 40), rec(Braw && Bbump && Bbeef && Batomic));
console.log(pad('D advisory/display ignored', 40), rec(D));

// ---------- §8 INDETERMINATE BOUNDARY ----------
console.log('\n=== INDETERMINATE BOUNDARY ===');
const ib = [
  ['trusted index .has throws', V.verify(E, { bindRawTx: false, chainHashIndex: { has(){ throw new Error('boom'); }, get(){} }, trustIndex: true }).outcome, 'INDETERMINATE'],
  ['malformed evidence (bad hex)', V.verify(merge(E, { blockHeader: 'zz'.repeat(80) }), { bindRawTx: false }).outcome, 'MALFORMED'],
  ['invalid PoW (tamper nonce)', V.verify(merge(E, { blockHeader: (() => { const b = Buffer.from(E.blockHeader, 'hex'); b[79] ^= 0xff; return b.toString('hex'); })() }), { bindRawTx: false }).outcome, 'FAILED'],
  ['unimplemented BEEF dep', V.verify(merge(strip(E, 'bump'), { beef: 'aa', proof: undefined }), { bindRawTx: false }).outcome, 'INDETERMINATE'],
];
for (const [name, got, exp] of ib) console.log(pad(name, 34), pad(exp, 20), pad(got, 20), rec(got === exp) + (got === 'VERIFIED' || got === 'VERIFIED-ISOLATION' ? '  <-- eval became VERIFIED!' : ''));

// ---------- §9 CHAIN LOADER / ANCHORING ----------
console.log('\n=== CHAIN LOADER / ANCHORING (§O) ===');
const bin = fs.readFileSync(FIX + '/test/headers-940000-to-940000.bin');
const mut = (b, fn) => { const c = Buffer.from(b); fn(c); return c; };
function loaderCase(name, bytes, expectReject) {
  let rejected = false, idx = null;
  try { idx = V.loadChain(bytes); } catch (e) { rejected = true; }
  const ok = expectReject ? rejected : !rejected;
  console.log(pad(name, 34), pad(expectReject ? 'reject' : 'load', 12), pad(rejected ? 'rejected' : 'loaded', 12), rec(ok));
  return idx;
}
const goodChain = loaderCase('valid anchored chain', bin, false);
loaderCase('wrong checkpoint (anchor hash)', mut(bin, c => { c[4] ^= 0xff; }), true);
loaderCase('missing/short prefix', bin.slice(0, 20), true);
loaderCase('broken prevHash', mut(bin, c => { c[44] ^= 0xff; }), true);
loaderCase('truncated file', bin.slice(0, 100), true);
// membership: a hash present in an UNRELATED index must NOT be accepted as chain membership
console.log('\n=== ANCHORING vs MERE PRESENCE ===');
const forgedIndex = new Map([[blockHash.toLowerCase(), 999999]]); // arbitrary map, not checkpoint-anchored
const forgedOutcome = V.verify(E, { bindRawTx: true, chainHashIndex: forgedIndex }).outcome;
// Spec §C-4/§O: membership is only meaningful for a checkpoint-ANCHORED index. A raw Map that
// did not come from loadChain() is caller-supplied trust; the loader is what enforces anchoring.
console.log(pad('arbitrary index w/ block hash', 34), '-> VERIFIED only via anchored loader; raw map =', forgedOutcome);
console.log('   (note: loadChain is the anchoring gate; a hand-built Map bypasses it by definition — see report)');

// ---------- TRUST BOUNDARY (chain-index provenance) ----------
console.log('\n=== TRUST BOUNDARY (chain-index provenance) ===');
{
  const bh = blockHash.toLowerCase();
  const loaded = V.loadChain(bin);                       // loader-anchored index (unforgeable)
  const arbitrary = new Map([[bh, 999999]]);             // caller-built, unanchored
  const plainCopy = new Map(loaded.hashIndex);           // same entries, no provenance
  // A. valid loader output -> membership usable (status not refused)
  const A = V.verify(E, { bindRawTx: true, chainHashIndex: loaded.hashIndex }).chainInclusion.status !== 'refused-unanchored';
  console.log(pad('A loader index accepted', 40), rec(A));
  // B. arbitrary index -> NOT VERIFIED (fails closed to isolation)
  const bOut = V.verify(E, { bindRawTx: true, chainHashIndex: arbitrary }).outcome;
  console.log(pad('B arbitrary index -> not VERIFIED', 40), rec(bOut !== 'VERIFIED') + '  (' + bOut + ')');
  // F. provenance cannot be forged: plain copy and reflection both refused
  const Fcopy = V.verify(E, { bindRawTx: true, chainHashIndex: plainCopy }).chainInclusion.status === 'refused-unanchored';
  const Fsyms = Object.getOwnPropertySymbols(loaded.hashIndex).length === 0; // nothing reflectable
  console.log(pad('F forged/copied index refused', 40), rec(Fcopy && Fsyms));
  // explicit opt-in still available for callers that assert anchoring out-of-band
  const optIn = V.verify(E, { bindRawTx: true, chainHashIndex: arbitrary, trustIndex: true }).outcome;
  console.log(pad('  trustIndex:true honored (opt-in)', 40), rec(optIn === 'VERIFIED'));
}

console.log('\n=== SUMMARY (independent, frozen) ===');
console.log('PASS ' + pass + '   FAIL ' + fail);
