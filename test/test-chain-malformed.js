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

// a fully valid single-hop chain still verifies
{ const r = run([hop()]); ok(!r.threw && r.result === 'VALID' && r.outcome === 'VERIFIED', 'valid single-hop chain -> VERIFIED [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome + '/' + r.result) + ']'); }

console.log('\n----------------------------------------');
console.log('PASSED: ' + pass + '   FAILED: ' + fail);
process.exit(fail ? 1 : 0);
