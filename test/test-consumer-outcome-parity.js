/*
 * test-consumer-outcome-parity.js — cross-consumer top-level outcome agreement.
 *
 * Run: node test/test-consumer-outcome-parity.js        (from the repo root)
 *      node test/test-consumer-outcome-parity.js --base  (negative control: runs the
 *                                                         same suite against chain.html
 *                                                         at git HEAD; MUST fail)
 *
 * WHY THIS SUITE EXISTS
 * The shared outcome enum (lib/headers.js) exists so that verifier/explorer/chain emit ONE
 * vocabulary. Its only value is that a given value means the SAME THING regardless of which
 * consumer emitted it. Nothing previously tested that: test-chain-malformed.js and
 * fuzz-chain-browser.js never load explorer.html, and the differential fuzzers compare
 * production against headers-node-independent/ — both single-envelope verifiers. So a
 * divergence between two SHIPPED consumers on identical evidence was invisible.
 *
 * It was real: chain.html returned VERIFIED where explorer.html and verifier.html returned
 * VERIFIED-ISOLATION for the same envelope with no header chain loaded. chain.html loads no
 * chain at all (no checkpoint anchoring, no inclusion index), so spec §G step 5 applies and
 * step 6 — "all required claims ESTABLISHED, including chain inclusion" — never can.
 *
 * This suite drives the SHIPPED verification functions extracted from the published HTML,
 * using the same vm patterns as test/test-verifier-malformed.js and test/fuzz-browser.js.
 * It reimplements no verification logic.
 *
 * LIMITATION, stated plainly: Node + a DOM stub, not a real browser. chain.html's UI wiring
 * throws under the stub, so verifyChain() is called directly. These are function-level
 * observations.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { execSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const BASE = process.argv.includes('--base');   // negative control
const ENV = JSON.parse(fs.readFileSync(path.join(ROOT, 'test/real-envelope.json'), 'utf8'));

let pass = 0, fail = 0;
const failures = [];
function ok(cond, msg) {
  if (cond) { pass++; console.log('PASS ' + msg); }
  else { fail++; failures.push(msg); console.log('FAIL ' + msg); }
}

// Read a file from the working tree, or from git HEAD under --base.
function src(rel) {
  if (BASE) return execSync('git show HEAD:' + rel, { cwd: ROOT, maxBuffer: 1 << 24 }).toString('utf8');
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

// ---------------------------------------------------------------------------
// shared context + DOM stub
// ---------------------------------------------------------------------------
function libCtx() {
  const c = {};
  // In a browser `window` IS the global object; lib/*.js attach their exports to it.
  // A separate stub object would silently divert every export out of scope.
  c.global = c; c.globalThis = c; c.self = c; c.window = c;
  c.performance = { now: () => 0 }; c.TextEncoder = TextEncoder;
  c.Date = Date; c.console = { log() {}, warn() {}, error() {} };
  c.JSON = JSON; c.BigInt = BigInt; c.Math = Math; c.Number = Number; c.String = String;
  c.Object = Object; c.Array = Array; c.Error = Error; c.TypeError = TypeError;
  c.RegExp = RegExp; c.Uint8Array = Uint8Array; c.DataView = DataView;
  c.ArrayBuffer = ArrayBuffer; c.isNaN = isNaN; c.parseInt = parseInt; c.parseFloat = parseFloat;
  vm.createContext(c);
  for (const f of ['crypto.js', 'encoding.js', 'headers.js', 'bump.js', 'beef.js'])
    vm.runInContext(src('lib/' + f), c);   // src() honours --base, so the control
  return c;                                 // covers lib/ wording as well as the HTML
}
function domStub(c) {
  const els = {};
  const el = (id) => els[id] || (els[id] = {
    _v: '', _tc: '', _html: '', _a: {}, _cls: {}, dataset: {}, style: {}, disabled: false,
    addEventListener(e, f) { this['_on' + e] = f; },
    _click() { this._onclick && this._onclick.call(this); },
    classList: {
      add(k) { els[id]._cls[k] = 1; }, remove(k) { delete els[id]._cls[k]; },
      contains(k) { return !!els[id]._cls[k]; }
    },
    setAttribute(k, v) { this._a[k] = v; }, getAttribute(k) { return this._a[k]; },
    focus() {}, blur() {}, appendChild() {}, removeChild() {},
    get value() { return this._v; }, set value(x) { this._v = x; },
    get textContent() { return this._tc; }, set textContent(x) { this._tc = String(x); },
    get innerHTML() { return this._html; }, set innerHTML(x) { this._html = String(x); },
    set className(x) {}, get checked() { return !!this._ck; }, set checked(x) { this._ck = x; }
  });
  c.document = { getElementById: el, createElement: () => el('_c'), addEventListener() {}, body: el('_b') };
  return els;
}

// ---------------------------------------------------------------------------
// shipped consumers
// ---------------------------------------------------------------------------
function explorer(env, chainIdx, loadFailed) {
  const c = libCtx(); domStub(c);
  const H = src('explorer.html');
  const s = H.indexOf('function sha256Single');
  const mark = "return 'Corrupted branch, wrong sibling, or mismatched header';\n    }";
  vm.runInContext('var chainHashIndex=null, chainLoadFailed=false;', c);
  vm.runInContext(H.slice(s, H.indexOf(mark) + mark.length), c);
  c.chainHashIndex = chainIdx === undefined ? null : chainIdx;
  c.chainLoadFailed = !!loadFailed;
  try { return { outcome: c.verify(env).result.outcome }; }
  catch (e) { return { threw: e.message }; }
}
function verifier(env) {
  const c = libCtx(); const els = domStub(c);
  const H = src('verifier.html');
  const S = H.slice(H.indexOf('(function() {'), H.indexOf('})();', H.indexOf('(function() {')) + 5);
  vm.runInContext(S, c);
  c.document.getElementById('envelope-input').value = JSON.stringify(env);
  ['result-box', 'result-title', 'checks', 'details', 'result-section'].forEach(i => c.document.getElementById(i));
  try { els['verify-btn']._click(); return { outcome: els['result-title']._a['data-outcome'] }; }
  catch (e) { return { threw: e.message }; }
}
function chain(envs) {
  const c = libCtx(); domStub(c);
  let body = src('chain.html');
  body = body.slice(body.indexOf('<script>') + 8, body.lastIndexOf('</script>'));
  const io = body.indexOf('(function() {');
  if (io >= 0) body = body.slice(io + 13, body.lastIndexOf('})();'));
  // UI wiring needs a real DOM; verifyChain() itself does not.
  try { vm.runInContext(body, c); } catch (_) { /* expected under the stub */ }
  if (typeof c.verifyChain !== 'function') return { threw: 'verifyChain unreachable' };
  try {
    const r = c.verifyChain(envs);
    return { outcome: r.outcome, result: r.result, anti: r.claimsNotEstablished || [] };
  } catch (e) { return { threw: e.message }; }
}

// ---------------------------------------------------------------------------
// evidence variants
// ---------------------------------------------------------------------------
const clone = (o) => JSON.parse(JSON.stringify(o));
const blockHash = (() => libCtx().hashHeader(ENV.blockHeader).toLowerCase())();
const idxHas = new Map([[blockHash, 940000]]);

const badMerkle = clone(ENV);
badMerkle.proof[0].hash = 'ff' + badMerkle.proof[0].hash.slice(2);
delete badMerkle.bump;                       // force the legacy path so the tamper bites

const badPoW = clone(ENV);
badPoW.blockHeader = badPoW.blockHeader.slice(0, 152) + 'ffffffff';

const badHex = clone(ENV);
badHex.blockHeader = 'zz'.repeat(80);

console.log('=== cross-consumer outcome parity' + (BASE ? '  [NEGATIVE CONTROL: chain.html at git HEAD]' : '') + ' ===\n');

// ---------------------------------------------------------------------------
// P1 — the core parity case. Fails against the pre-fix implementation.
// ---------------------------------------------------------------------------
{
  const e = explorer(ENV, null), v = verifier(ENV), c = chain([ENV]);
  console.log('   [P1] explorer=' + e.outcome + '  verifier=' + v.outcome + '  chain=' + c.outcome);
  ok(e.outcome === 'VERIFIED-ISOLATION', 'P1 explorer, no chain -> VERIFIED-ISOLATION');
  ok(v.outcome === 'VERIFIED-ISOLATION', 'P1 verifier, no chain -> VERIFIED-ISOLATION');
  ok(c.outcome === 'VERIFIED-ISOLATION', 'P1 chain, no chain -> VERIFIED-ISOLATION');
  ok(e.outcome === v.outcome && v.outcome === c.outcome,
    'P1 all three consumers AGREE on identical evidence');
}

// ---------------------------------------------------------------------------
// P2 — chain.html must never claim VERIFIED, since it cannot establish inclusion.
// ---------------------------------------------------------------------------
{
  const c = chain([ENV]);
  ok(c.result === 'VALID', 'P2 precondition: chain reports result VALID');
  ok(c.outcome !== 'VERIFIED',
    'P2 chain never emits VERIFIED (inclusion is never attempted) [got ' + c.outcome + ']');
}

// ---------------------------------------------------------------------------
// P3 — chain.html states its inclusion scope boundary explicitly, rather than
// leaving it to be inferred from the VERIFIED-ISOLATION label.
// ---------------------------------------------------------------------------
{
  const c = chain([ENV]);
  const ids = c.anti.map(a => a.id);
  ok(c.anti.some(a => /inclusion/i.test(a.id)),
    'P3 chain carries an explicit chain-inclusion anti-claim [ids: ' + ids.join(',') + ']');
  ok(c.anti.every(a => a.scope === 'not-attempted'),
    'P3 every chain anti-claim is scope:not-attempted (boundary, not evidence failure)');
}

// ---------------------------------------------------------------------------
// P4 — guard against over-correction: a genuinely anchored chain is still VERIFIED.
// ---------------------------------------------------------------------------
{
  const e = explorer(ENV, idxHas);
  ok(e.outcome === 'VERIFIED',
    'P4 explorer WITH anchored chain containing the block -> VERIFIED [got ' + e.outcome + ']');
}

// ---------------------------------------------------------------------------
// P5-P7 — precedence must be unchanged by the correction.
// ---------------------------------------------------------------------------
function allThree(name, env, expect) {
  const e = explorer(env, null), v = verifier(env), c = chain([env]);
  ok(e.outcome === expect, name + ' explorer -> ' + expect + ' [got ' + (e.threw ? 'THREW' : e.outcome) + ']');
  ok(v.outcome === expect, name + ' verifier -> ' + expect + ' [got ' + (v.threw ? 'THREW' : v.outcome) + ']');
  ok(c.outcome === expect, name + ' chain -> ' + expect + ' [got ' + (c.threw ? 'THREW' : c.outcome) + ']');
}
allThree('P5 invalid Merkle proof', badMerkle, 'FAILED');
allThree('P6 invalid PoW', badPoW, 'FAILED');
allThree('P7 malformed header (bad hex)', badHex, 'MALFORMED');

// ---------------------------------------------------------------------------
// P8 — an anti-claim must contain no unconditional positive assertion. The shared
// most-work-chain text previously opened by asserting that a checkpoint-anchored
// chain "is verified", which was false for any consumer that loads no chain.
// ---------------------------------------------------------------------------
{
  const c = chain([ENV]);
  const bad = c.anti.filter(a => /checkpoint-anchored[^.]*is verified/i.test(a.detail || ''));
  ok(bad.length === 0,
    'P8 no anti-claim asserts a checkpoint-anchored chain "is verified"' +
    (bad.length ? ' [offender: ' + bad[0].id + ']' : ''));
  // The negative assertion itself must survive the rewrite (mirrors test-adversarial H6).
  const mw = c.anti.find(a => a.id === 'most-work-chain');
  ok(mw && /cumulative proof-of-work|most-work/i.test(mw.detail),
    'P8 most-work anti-claim still names cumulative PoW / most-work selection');
}

console.log('\n----------------------------------------');
console.log('PASSED: ' + pass + '   FAILED: ' + fail);
if (fail) { console.log('\nFAILURES:'); failures.forEach(f => console.log('  - ' + f)); }

if (BASE) {
  console.log('\nNEGATIVE CONTROL: failures above are expected against the pre-fix source.');
  process.exit(fail > 0 ? 0 : 1);   // control passes only if the suite FAILED
}
process.exit(fail ? 1 : 0);
