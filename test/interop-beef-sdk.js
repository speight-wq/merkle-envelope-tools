'use strict';
/*
 * test/interop-beef-sdk.js - THREE-WAY BEEF/Atomic-BEEF conformance:
 *
 *     production lib/beef.js  <->  independent test/oracle-beef.js  <->  third-party @bsv/sdk
 *
 * PURPOSE: conformance / interoperability, not making the SDK the source of truth. The
 * normative reference is VERIFICATION-SEMANTICS-SPEC.md; production is the implementation under
 * test; oracle-beef.js is the independent wire-format interpreter (Phase 6); @bsv/sdk is a
 * third, genuinely separate implementation. Each path interprets the SAME raw BEEF bytes.
 *
 * ENVIRONMENT NOTE: this repository is intentionally zero-dependency; @bsv/sdk is NOT installed
 * here and the environment has no network to install it. This harness therefore:
 *   - loads @bsv/sdk through a guarded require; if it is absent it SKIPS the SDK dimension
 *     cleanly (exit 0) so the zero-dependency build and `npm test` are unaffected;
 *   - never fabricates an SDK result and never recreates SDK internals;
 *   - feature-detects the SDK public API at runtime (Beef / Transaction / MerklePath and their
 *     methods) rather than assuming a specific version's surface - any dimension the installed
 *     SDK does not expose is reported "unavailable", not approximated;
 *   - ALWAYS runs a machinery self-check (a planted production-vs-oracle disagreement, the two
 *     implementations that ARE present) to prove the differential can detect disagreement even
 *     when the SDK is absent.
 *
 * When a developer runs this with `@bsv/sdk` installed, the full three-way differential runs.
 *
 * Run:
 *   node test/interop-beef-sdk.js
 *   node test/interop-beef-sdk.js --seed 20260701 --iters 20000   (mutations, if SDK present)
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
require(path.join(ROOT, 'lib/crypto.js'));
require(path.join(ROOT, 'lib/encoding.js'));
require(path.join(ROOT, 'lib/headers.js'));
const BUMP = require(path.join(ROOT, 'lib/bump.js'));
const BEEF = require(path.join(ROOT, 'lib/beef.js'));
const O = require(path.join(ROOT, 'test/oracle-beef.js'));
const ENV = JSON.parse(fs.readFileSync(path.join(ROOT, 'test/real-envelope.json'), 'utf8'));

// ---- deterministic valid corpus (production builds the INPUT; all three parse it) ---------
function buildCorpus() {
  const out = [];
  const S = (x) => String(x).toLowerCase();
  const le = (n, b) => { const x = Buffer.alloc(b); let v = n; for (let i = 0; i < b; i++) { x[i] = v & 0xff; v = Math.floor(v / 256); } return x; };
  const vi = (n) => n < 0xfd ? Buffer.from([n]) : Buffer.concat([Buffer.from([0xfd]), le(n, 2)]);
  const child = (pt, tag) => Buffer.concat([le(1, 4), vi(1), Buffer.from(pt, 'hex').reverse(), le(0, 4), vi(3), Buffer.from([tag, tag, tag]), le(0xffffffff, 4), vi(1), le(1000, 8), vi(2), Buffer.from([0x51, 0x51]), le(0, 4)]).toString('hex');
  try {
    const bump = BUMP.fromHex(ENV.bump);
    const txid0 = BEEF.txidOf(ENV.rawTx);
    const raw1 = child(txid0, 0xab), txid1 = BEEF.txidOf(raw1);
    const raw2 = child(txid1, 0xcd), txid2 = BEEF.txidOf(raw2);
    out.push({ id: 'plain', hex: S(BEEF.build({ bumps: [bump], transactions: [{ rawHex: ENV.rawTx, bumpIndex: 0 }] })), atomic: false });
    out.push({ id: 'multi', hex: S(BEEF.build({ bumps: [bump], transactions: [{ rawHex: ENV.rawTx, bumpIndex: 0 }, { rawHex: raw1, bumpIndex: null }] })), atomic: false });
    const chain3 = S(BEEF.build({ bumps: [bump], transactions: [{ rawHex: ENV.rawTx, bumpIndex: 0 }, { rawHex: raw1, bumpIndex: null }, { rawHex: raw2, bumpIndex: null }] }));
    out.push({ id: 'chain3', hex: chain3, atomic: false });
    out.push({ id: 'atomic', hex: S(BEEF.wrapAtomic(S(BEEF.build({ bumps: [bump], transactions: [{ rawHex: ENV.rawTx, bumpIndex: 0 }, { rawHex: raw1, bumpIndex: null }] })), txid1)), atomic: true, subject: txid1 });
    out.push({ id: 'atomic3', hex: S(BEEF.wrapAtomic(chain3, txid2)), atomic: true, subject: txid2 });
  } catch (_) { }
  return out;
}

// ---- normalized interpreters -------------------------------------------------------------
// production
function readProduction(hex) {
  try {
    const p = BEEF.parse(hex);
    return { ok: true, atomic: p.atomicSubject || null, count: p.transactions.length,
      txids: p.transactions.map(t => t.txid),
      prevs: p.transactions.map(t => (t.inputs || []).map(i => i.prevTxid)),
      roots: p.transactions.map(t => t.bumpIndex == null ? null : safe(() => BUMP.merkleRoot(p.bumps[t.bumpIndex], t.txid))) };
  } catch (e) { return { ok: false, err: e && e.name }; }
}
// independent oracle
function readOracle(hex) {
  try {
    const o = O.parseBeef(hex);
    return { ok: true, atomic: o.atomicSubject || null, count: o.transactions.length,
      txids: o.transactions.map(t => t.txid),
      prevs: o.transactions.map(t => (t.inputs || []).map(i => i.prevTxid)),
      roots: o.transactions.map(t => t.bumpIndex == null ? null : safe(() => O.bumpRoot(o.bumps[t.bumpIndex], t.txid))) };
  } catch (e) { return { ok: false, err: e && e.name }; }
}
function safe(fn) { try { return fn(); } catch (_) { return 'ERR'; } }

// ---- third-party SDK adapter (feature-detected; never invents API) -----------------------
function loadSdk() {
  let SDK = null;
  try { SDK = require('@bsv/sdk'); } catch (_) { return null; }
  const caps = { present: true, version: null, Beef: !!SDK.Beef, Transaction: !!SDK.Transaction, MerklePath: !!SDK.MerklePath };
  try { caps.version = require('@bsv/sdk/package.json').version; } catch (_) { }
  return { SDK, caps };
}
// Build a normalized SDK reading using only whatever the installed SDK actually exposes.
function readSdk(sdk, hex) {
  const { SDK } = sdk;
  const bytes = Array.from(Buffer.from(hex, 'hex'));
  // BEEF parse: try the documented constructors, feature-detected
  let beef = null, parseErr = null;
  try {
    if (SDK.Beef && typeof SDK.Beef.fromBinary === 'function') beef = SDK.Beef.fromBinary(bytes);
    else if (SDK.Beef && typeof SDK.Beef.fromString === 'function') beef = SDK.Beef.fromString(hex, 'hex');
    else return { ok: false, unavailable: 'Beef parser not exposed' };
  } catch (e) { parseErr = (e && e.message) || String(e); }
  if (!beef) return { ok: false, err: parseErr || 'parse failed' };

  const res = { ok: true, atomic: null, count: null, txids: [], prevs: [], roots: [], notes: [] };
  // transactions: the SDK Beef shape varies; probe common shapes without assuming one
  const txsArr = beef.txs || (typeof beef.getTransactions === 'function' ? safe(() => beef.getTransactions()) : null);
  if (Array.isArray(txsArr)) {
    res.count = txsArr.length;
    for (const bt of txsArr) {
      // a BeefTx may hold a .tx (Transaction) or raw bytes; probe for a txid accessor
      const tx = bt && (bt.tx || bt.transaction || bt);
      let txid = null;
      if (tx && typeof tx.id === 'function') txid = safe(() => tx.id('hex'));
      else if (bt && (bt.txid || bt.txID)) txid = (bt.txid || bt.txID);
      res.txids.push(txid);
      const ins = tx && Array.isArray(tx.inputs) ? tx.inputs.map(i => i && (i.sourceTXID || i.prevTxid || (i.sourceTransaction && safe(() => i.sourceTransaction.id('hex'))))) : [];
      res.prevs.push(ins);
      // merkle root via MerklePath if present on the BeefTx
      let root = null;
      const mp = bt && (bt.bumpIndex != null && beef.bumps ? beef.bumps[bt.bumpIndex] : (bt.merklePath || null));
      if (mp && typeof mp.computeRoot === 'function' && txid) root = safe(() => mp.computeRoot(txid));
      res.roots.push(root);
    }
  } else {
    res.notes.push('SDK Beef transaction list shape not recognized by adapter');
  }
  // atomic subject, if the SDK exposes it
  if (beef.atomicTxid) res.atomic = beef.atomicTxid;
  else if (typeof beef.getAtomicTxid === 'function') res.atomic = safe(() => beef.getAtomicTxid());
  return res;
}

// ---- three-way / two-way comparison ------------------------------------------------------
function norm(v) { return v == null ? null : String(v).toLowerCase(); }
function cmpField(a, b) { return norm(a) === norm(b); }
function compareTriple(prod, orac, sdk) {
  // returns { disagreements: [...] }; only compares fields all present sides expose
  const dis = [];
  const sides = { prod, orac };
  if (sdk) sides.sdk = sdk;
  // acceptance
  const acc = Object.entries(sides).map(([k, v]) => [k, !!v.ok]);
  if (new Set(acc.map(x => x[1])).size > 1) dis.push('accept/reject: ' + acc.map(x => x[0] + '=' + (x[1] ? 'ok' : 'rej')).join(' '));
  if (prod.ok && orac.ok) {
    if (prod.count !== orac.count) dis.push('count prod=' + prod.count + ' orac=' + orac.count);
    else for (let i = 0; i < prod.count; i++) {
      if (!cmpField(prod.txids[i], orac.txids[i])) dis.push('txid@' + i + ' prod/orac');
      if (JSON.stringify((prod.prevs[i] || []).map(norm)) !== JSON.stringify((orac.prevs[i] || []).map(norm))) dis.push('prevs@' + i + ' prod/orac');
      if (norm(prod.roots[i]) !== norm(orac.roots[i])) dis.push('root@' + i + ' prod/orac');
    }
    if (norm(prod.atomic) !== norm(orac.atomic)) dis.push('atomic prod/orac');
  }
  if (sdk && sdk.ok && prod.ok) {
    if (sdk.count != null && sdk.count !== prod.count) dis.push('count sdk=' + sdk.count + ' prod=' + prod.count);
    if (sdk.count === prod.count) for (let i = 0; i < prod.count; i++) {
      if (sdk.txids[i] != null && !cmpField(sdk.txids[i], prod.txids[i])) dis.push('txid@' + i + ' sdk/prod');
      if (sdk.roots[i] != null && norm(sdk.roots[i]) !== norm(prod.roots[i])) dis.push('root@' + i + ' sdk/prod');
    }
    if (sdk.atomic != null && norm(sdk.atomic) !== norm(prod.atomic)) dis.push('atomic sdk/prod');
  }
  return dis;
}

// ---- run ---------------------------------------------------------------------------------
const corpus = buildCorpus();
if (!corpus.length) { console.error('could not build BEEF corpus'); process.exit(1); }
const sdk = loadSdk();

console.log('Merkle Envelope Tools - three-way BEEF conformance (production / oracle / @bsv/sdk)\n');

// Machinery self-check (ALWAYS runs, SDK or not): a planted production-vs-oracle disagreement
// must be detected by the comparator. This proves the differential can flag disagreement.
(function machinerySelfCheck() {
  const good = compareTriple(readProduction(corpus[0].hex), readOracle(corpus[0].hex), null);
  const p = readProduction(corpus[0].hex); const o = readOracle(corpus[0].hex);
  o.txids[0] = 'deadbeef'.repeat(8); // planted disagreement (adapter-level, not touching any impl)
  const planted = compareTriple(p, o, null);
  const ok = good.length === 0 && planted.some(d => d.startsWith('txid@0'));
  console.log('Machinery self-check (planted prod-vs-oracle disagreement detected): ' + (ok ? 'PASS' : 'FAIL'));
  if (!ok) { console.log('  self-check failed; comparator cannot detect disagreement'); process.exit(1); }
})();

if (!sdk) {
  console.log('\n@bsv/sdk: NOT INSTALLED in this environment (zero-dependency repo; no network to install).');
  console.log('Three-way SDK comparison: SKIPPED (dimension unavailable, not approximated).');
  console.log('Production vs independent oracle agreement is covered by test/fuzz-beef-oracle.js.');
  console.log('\nRESULT: PASS (SDK dimension unavailable; harness ready + self-check passed)');
  process.exit(0);
}

// SDK present -> real three-way differential over the valid corpus (+ optional mutations)
console.log('@bsv/sdk version: ' + (sdk.caps.version || 'unknown'));
console.log('SDK capabilities: ' + JSON.stringify(sdk.caps) + '\n');
let disagreements = 0, exceptions = 0;
const rows = [];
for (const c of corpus) {
  const prod = readProduction(c.hex), orac = readOracle(c.hex);
  let sres = null; try { sres = readSdk(sdk, c.hex); } catch (e) { exceptions++; sres = { ok: false, err: 'adapter threw: ' + (e && e.message) }; }
  const dis = compareTriple(prod, orac, sres);
  rows.push({ id: c.id, prod: prod.ok, orac: orac.ok, sdk: sres && (sres.ok ? 'ok' : (sres.unavailable ? 'unavail' : 'rej')), dis });
  if (dis.length) disagreements += dis.length;
}
for (const r of rows) console.log('  ' + r.id.padEnd(9) + ' prod=' + r.prod + ' orac=' + r.orac + ' sdk=' + r.sdk + (r.dis.length ? '  DISAGREE: ' + r.dis.join('; ') : '  agree'));
console.log('\nDisagreements: ' + disagreements + ' | adapter exceptions: ' + exceptions);
console.log(disagreements ? '\nRESULT: DISAGREEMENTS FOUND - investigate + classify (see report guidance)' : '\nRESULT: PASS (three-way conformance on comparable dimensions at this corpus)');
process.exit(disagreements ? 1 : 0);
