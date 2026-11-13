'use strict';
/*
 * test/test-chain-malformed.js - regression guard for the shipped chain.html verifyChain path.
 *
 * chain.html was audited (Phase 5) and found sound: result defaults to FAILED and is set VALID
 * only after every phase passes, every evidence field is required and hex-validated up front,
 * and a hop exception is caught -> INDETERMINATE. No production defect was found. These cases
 * lock in that behaviour: a single required field missing/empty/malformed yields a typed
 * rejection (never VALID/VERIFIED, never an uncaught throw), and a fully valid single-hop chain
 * verifies.
 *
 * Runs the shipped chain.html IIFE body unchanged in a vm to expose verifyChain.
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
const ENV = JSON.parse(fs.readFileSync(path.join(ROOT, 'test/real-envelope.json'), 'utf8'));
const FIXED = (Buffer.from(ENV.blockHeader, 'hex').readUInt32LE(68) + 31536000) * 1000;

function buildContext() {
  const H = fs.readFileSync(path.join(ROOT, 'chain.html'), 'utf8');
  const app = [...H.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).find(s => s.includes('verifyChain'));
  const start = app.indexOf('(function() {');
  const body = app.slice(start + '(function() {'.length, app.lastIndexOf('})();'));
  const c = {}; c.global = c; c.window = c; c.performance = { now: () => 0 };
  c.TextEncoder = TextEncoder; c.console = { log() {}, warn() {}, error() {} };
  c.Date = class extends Date { constructor(...a) { if (a.length) super(...a); else super(FIXED); } static now() { return FIXED; } };
  const els = {}; const el = (id) => els[id] || (els[id] = { _v: '', _tc: '', _a: {}, addEventListener() {}, classList: { add() {}, remove() {} }, get value() { return this._v; }, set value(x) { this._v = x; }, set textContent(x) {}, set className(x) {}, set innerHTML(x) {}, setAttribute(k, v) { this._a[k] = v; }, querySelector() { return null; }, style: {} });
  c.document = { getElementById: el, addEventListener() {}, querySelector() { return null; }, querySelectorAll() { return []; }, createElement() { return el('x'); } };
  vm.createContext(c);
  for (const f of ['crypto.js', 'encoding.js', 'headers.js', 'bump.js', 'beef.js']) vm.runInContext(fs.readFileSync(path.join(ROOT, 'lib', f), 'utf8'), c);
  vm.runInContext(body, c);
  return c;
}
const CTX = buildContext();
const ACCEPT = new Set(['VERIFIED', 'VERIFIED-ISOLATION']);
function run(chain) { try { const r = CTX.verifyChain(chain); return { outcome: r.outcome, result: r.result }; } catch (e) { return { threw: e.message }; } }
const clone = (o) => JSON.parse(JSON.stringify(o));
const hop = () => { const e = clone(ENV); delete e.bump; delete e.beef; delete e.atomicBeef; return e; }; // chain uses legacy proof

let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log((c ? 'PASS ' : 'FAIL ') + m); };
const rejected = (r) => !r.threw && r.result !== 'VALID' && !ACCEPT.has(r.outcome);

// missing each required field -> typed rejection, never positive, never throws
for (const f of ['blockHeader', 'txid', 'rawTx', 'proof']) {
  const r = run([(() => { const e = hop(); delete e[f]; return e; })()]);
  ok(rejected(r), 'missing ' + f + ' -> typed rejection (not VALID) [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome + '/' + r.result) + ']');
}
// empty each string field
for (const f of ['blockHeader', 'txid', 'rawTx']) {
  const r = run([Object.assign(hop(), { [f]: '' })]);
  ok(rejected(r), 'empty ' + f + ' -> typed rejection [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome + '/' + r.result) + ']');
}
// non-hex header / proof hash / txid
ok(rejected(run([Object.assign(hop(), { blockHeader: 'g'.repeat(160) })])), 'non-hex header -> typed rejection');
ok(rejected(run([Object.assign(hop(), { txid: 'g'.repeat(64) })])), 'non-hex txid -> typed rejection');
{ const e = hop(); if (e.proof && e.proof.length) e.proof[0].hash = 'g'.repeat(64); ok(rejected(run([e])), 'non-hex proof hash -> typed rejection'); }
// proof not an array
ok(rejected(run([Object.assign(hop(), { proof: {} })])), 'proof non-array -> typed rejection');
// empty chain
ok(rejected(run([])), 'empty chain array -> typed rejection');
// wrong txid (valid hex, does not match rawTx)
ok(rejected(run([Object.assign(hop(), { txid: 'ab'.repeat(32) })])), 'wrong txid -> typed rejection');

// A fully valid single-hop chain still verifies. The outcome is VERIFIED-ISOLATION, not
// VERIFIED: chain.html loads no header chain, so inclusion is NOT-ESTABLISHED by absence
// (spec §G step 5). This expectation previously read 'VERIFIED', which encoded the
// over-claim corrected in this commit — it was not relaxed to make a test pass.
{ const r = run([hop()]); ok(!r.threw && r.result === 'VALID' && r.outcome === 'VERIFIED-ISOLATION', 'valid single-hop chain -> VERIFIED-ISOLATION [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome + '/' + r.result) + ']'); }

// ---------------------------------------------------------------------------
// Evidence identity must survive a rejection (EF-*).
//
// inputFingerprint is a pure function of the submitted envelopes. Spec §K defines it as
// an evidence-identity claim — "equal digest => same inputs, never same verdict" — so it
// must not depend on the verdict. It was previously computed only on the Phase 3+ return
// paths, so a Phase 2 ordering rejection reported inputFingerprint: null: the report named
// no evidence, could not be reproduced or compared, and exported as
// 'chain-verification-unknown'. Two FAILED verdicts were differently auditable depending
// only on which phase caught the problem.
//
// These assertions fail against the pre-fix chain.html.
// ---------------------------------------------------------------------------
function raw(chain) { try { return CTX.verifyChain(chain); } catch (e) { return { threw: e.message }; } }
const FP = /^[0-9a-f]{32}$/;

// EF-1 a valid chain still carries one (guards against the fix breaking the normal path)
{ const r = raw([hop()]);
  ok(!r.threw && FP.test(r.inputFingerprint || ''), 'EF-1 valid chain carries an inputFingerprint'); }

// EF-2 the Phase 2 ordering rejection — the case that regressed — now carries one.
// Two structurally valid but unrelated hops: neither spends the other.
{ const r = raw([hop(), hop()]);
  ok(!r.threw && r.failureType === 'ORDERING_INVALID', 'EF-2 precondition: unlinked pair -> ORDERING_INVALID');
  ok(!r.threw && FP.test(r.inputFingerprint || ''),
     'EF-2 ORDERING_INVALID rejection carries an inputFingerprint [got ' + (r.threw ? 'THREW' : r.inputFingerprint) + ']'); }

// EF-3 a Phase 3 cryptographic rejection carries one (pre-existing behaviour, locked in)
{ const e = hop(); e.proof[0].hash = e.proof[0].hash.replace(/.$/, c => (c === '0' ? '1' : '0'));
  const r = raw([e]);
  ok(!r.threw && r.result !== 'VALID' && FP.test(r.inputFingerprint || ''),
     'EF-3 Phase-3 cryptographic rejection carries an inputFingerprint'); }

// EF-4 identity is a function of the INPUT, not the verdict: a rejected chain and the same
// bytes re-submitted must fingerprint identically, and different evidence must differ.
{ const a = raw([hop(), hop()]), b = raw([hop(), hop()]);
  ok(a.inputFingerprint === b.inputFingerprint, 'EF-4 same rejected evidence -> same fingerprint');
  const c = raw([hop()]);
  ok(c.inputFingerprint !== a.inputFingerprint, 'EF-4 different evidence -> different fingerprint'); }

// EF-5 hop ORDER is semantically meaningful, so reversing a chain must change the identity.
{ const x = hop(), y = Object.assign(hop(), { vout: (hop().vout || 0) + 1 });
  const f1 = raw([x, y]).inputFingerprint, f2 = raw([y, x]).inputFingerprint;
  ok(FP.test(f1 || '') && FP.test(f2 || '') && f1 !== f2,
     'EF-5 reversed chain -> different fingerprint (order is meaningful)'); }

// EF-6 no evidence means no evidence identity. Serialising zero envelopes yields SHA-256 of
// zero bytes (e3b0c442...), a constant that identifies nothing; emitting it would assert
// that evidence had been identified when none was submitted.
{ const r = raw([]);
  ok(!r.threw && r.inputFingerprint === null, 'EF-6 empty chain -> inputFingerprint null, not the empty-input hash');
  ok(!r.threw && !/^e3b0c442/.test(r.inputFingerprint || ''), 'EF-6 empty chain never reports the SHA-256 of zero bytes'); }

// EF-7 fail closed: an envelope malformed enough to be unserialisable must leave the
// fingerprint null and must NOT crash out of verification.
{ const e = hop(); delete e.txid;
  const r = raw([e]);
  ok(!r.threw, 'EF-7 unserialisable envelope does not throw out of verifyChain');
  ok(!r.threw && r.result !== 'VALID', 'EF-7 unserialisable envelope still yields a typed rejection');
  ok(!r.threw && r.inputFingerprint === null, 'EF-7 unserialisable envelope -> fingerprint null (fail closed)'); }

console.log('\n----------------------------------------');
console.log('PASSED: ' + pass + '   FAILED: ' + fail);
process.exit(fail ? 1 : 0);
