'use strict';
/*
 * test/test-verifier-malformed.js - regression for the Phase-4B-FIX false-acceptance defects.
 *
 * The shipped verifier.html previously left `allPassed` true when required evidence was absent:
 *   - missing/empty blockHeader  -> reported VERIFIED-ISOLATION ("VALID PROOF") with no header,
 *     no PoW, and no merkle check.
 *   - header present but no proof -> reported VERIFIED-ISOLATION with no merkle proof at all.
 * A valid txid/rawTx binding alone must never produce a positive proof verdict. These cases
 * assert the shipped verifier returns a rejection outcome (MALFORMED / FAILED), never a
 * VERIFIED* outcome, and never throws; and that valid envelopes are unchanged.
 *
 * Drives the SHIPPED verifier.html click handler via the same DOM-stub the other harnesses use.
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
const ENV = JSON.parse(fs.readFileSync(path.join(ROOT, 'test/real-envelope.json'), 'utf8'));
const HTML = fs.readFileSync(path.join(ROOT, 'verifier.html'), 'utf8');
const SCRIPT = HTML.slice(HTML.indexOf('(function() {'), HTML.indexOf('})();', HTML.indexOf('(function() {')) + 5);

function run(env) {
  const els = {};
  const el = (id) => els[id] || (els[id] = {
    _v: '', _tc: '', _a: {},
    addEventListener(e, f) { this['_' + e] = f; }, classList: { add() {}, remove() {} },
    get value() { return this._v; }, set value(x) { this._v = x; },
    set textContent(x) { this._tc = x; }, set className(x) {}, set innerHTML(x) {},
    setAttribute(k, v) { this._a[k] = v; }, get dataset() { return {}; }
  });
  const c = {}; c.global = c; c.document = { getElementById: el }; c.performance = { now: () => 0 };
  c.TextEncoder = TextEncoder; c.console = { log() {}, warn() {}, error() {} }; c.Date = Date;
  c.chainHashIndex = null; c.chainLoadFailed = false;
  vm.createContext(c);
  for (const f of ['crypto.js', 'encoding.js', 'headers.js', 'bump.js', 'beef.js']) vm.runInContext(fs.readFileSync(path.join(ROOT, 'lib', f), 'utf8'), c);
  vm.runInContext(SCRIPT, c);
  el('envelope-input').value = JSON.stringify(env);
  try { el('verify-btn')._click(); return { outcome: els['result-title']._a['data-outcome'] }; }
  catch (e) { return { threw: e.message }; }
}
const clone = (o) => JSON.parse(JSON.stringify(o));
const ACCEPT = new Set(['VERIFIED', 'VERIFIED-ISOLATION']);

let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log((c ? 'PASS ' : 'FAIL ') + m); };

// 1. missing blockHeader -> MALFORMED, no throw, not a positive verdict
let r = run((() => { const e = clone(ENV); delete e.blockHeader; return e; })());
ok(!r.threw && r.outcome === 'MALFORMED', 'missing blockHeader -> MALFORMED [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome) + ']');

// 2. empty blockHeader -> MALFORMED
r = run(Object.assign(clone(ENV), { blockHeader: '' }));
ok(!r.threw && r.outcome === 'MALFORMED', 'empty blockHeader -> MALFORMED [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome) + ']');

// 3. null blockHeader -> MALFORMED (falsy)
r = run(Object.assign(clone(ENV), { blockHeader: null }));
ok(!r.threw && r.outcome === 'MALFORMED', 'null blockHeader -> MALFORMED [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome) + ']');

// 4. malformed/truncated header -> a typed rejection (MALFORMED), no throw
r = run(Object.assign(clone(ENV), { blockHeader: '00' }));
ok(!r.threw && !ACCEPT.has(r.outcome), 'truncated header -> typed rejection (not positive) [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome) + ']');

// 5. header present but NO proof (no bump/beef/proof) -> FAILED, never positive
r = run((() => { const e = clone(ENV); delete e.bump; delete e.beef; delete e.atomicBeef; delete e.proof; return e; })());
ok(!r.threw && r.outcome === 'FAILED', 'header present, no proof -> FAILED (not VALID PROOF) [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome) + ']');

// 6. the core property: a valid txid/rawTx binding must NOT yield a positive proof when the
//    required header is absent (this is the exact defect)
r = run((() => { const e = clone(ENV); delete e.blockHeader; return e; })());
ok(!r.threw && !ACCEPT.has(r.outcome), 'valid txid/rawTx alone (no header) is NOT a positive proof [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome) + ']');

// 7. valid BUMP envelope still VERIFIED-ISOLATION (unchanged)
r = run(ENV);
ok(!r.threw && r.outcome === 'VERIFIED-ISOLATION', 'valid BUMP envelope still VERIFIED-ISOLATION [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome) + ']');

// 8. valid legacy-proof envelope still VERIFIED-ISOLATION (unchanged)
r = run((() => { const e = clone(ENV); delete e.bump; return e; })());
ok(!r.threw && r.outcome === 'VERIFIED-ISOLATION', 'valid legacy-proof envelope still VERIFIED-ISOLATION [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome) + ']');

console.log('\n----------------------------------------');
console.log('PASSED: ' + pass + '   FAILED: ' + fail);
process.exit(fail ? 1 : 0);
