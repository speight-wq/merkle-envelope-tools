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
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const BASE = process.argv.includes('--base');   // negative control

// Minimum number of assertions that MUST detect a defect in the pre-fix fixtures.
// "At least one" is too weak — it would tolerate a collapse in detection coverage.
// This is the count observed when the control was written (P1 x2, P2, P3, P8). More is
// fine; fewer fails loudly. Update deliberately if the assertion set changes.
const MIN_DETECTIONS = 5;
const ENV = JSON.parse(fs.readFileSync(path.join(ROOT, 'test/real-envelope.json'), 'utf8'));

let pass = 0, fail = 0;
const failures = [];
function ok(cond, msg) {
  if (cond) { pass++; console.log('PASS ' + msg); }
  else {
    fail++; failures.push(msg);
    // Under --base a failing assertion is the EXPECTED outcome: it is the control
    // detecting the original defect. Labelling it 'FAIL' would misread as a problem,
    // and would also look like a real failure to run-all.js's output scanner.
    // FIX-0* are control-integrity assertions and are genuine failures in both modes.
    const expected = BASE && msg.indexOf('FIX-0') !== 0;
    console.log((expected ? 'DETECT ' : 'FAIL ') + msg);
  }
}

// ---------------------------------------------------------------------------
// NEGATIVE-CONTROL BASELINE
//
// This control previously read the pre-fix source with `git show HEAD:<file>`. Once
// the fix was committed, HEAD *contained* the fix, so the control compared the fix
// against itself, reported zero failures, and printed text that read like success.
//
// The baseline is now two immutable fixtures: the exact pre-fix chain.html and
// lib/headers.js, taken verbatim from commit b743fccb (the last commit before the
// chain-outcome corrections landed). They are the original files, not
// reconstructions, so they exhibit the original defects by being the original code.
//
// Only those two files were changed by the fix, so only those two are substituted.
// explorer.html and verifier.html are read from the working tree in both modes:
// they were not part of the defect, and the control's job is to prove the parity
// assertions can detect chain.html diverging from them.
//
// FIX-0 below pins each fixture's SHA-256 and checks it still exhibits its defect,
// so fixture rot is an explicit, diagnosable failure rather than a silent one.
// No network and no git history are required.
// ---------------------------------------------------------------------------
const FIXTURES = {
  'chain.html':     { rel: 'test/fixtures/prefix-chain-overclaim.html',
                      sha: '2f4b95ca84577eeb4085405f4a5cebe007042d602add8f66c4f93b139f2ade0e',
                      // pre-fix: unconditional VERIFIED, and no VERIFIED_ISOLATION anywhere
                      defect: t => /VALID'\) return O\.VERIFIED;/.test(t) &&
                                   t.indexOf('VERIFIED_ISOLATION') === -1 &&
                                   t.indexOf('chain-inclusion-this-consumer') === -1 },
  'lib/headers.js': { rel: 'test/fixtures/prefix-anticlaim-headers.js',
                      sha: 'f83c83e9459eea6eade8f0a4680fa1a3d5d41637edf57602f632fb1edf431a9a',
                      // pre-fix: anti-claim opens with an unconditional positive assertion
                      defect: t => t.indexOf('policy is verified') !== -1 }
};

// Read a file from the working tree, or from its immutable pre-fix fixture under --base.
function src(rel) {
  if (BASE && FIXTURES[rel]) return fs.readFileSync(path.join(ROOT, FIXTURES[rel].rel), 'utf8');
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

console.log('=== cross-consumer outcome parity' +
  (BASE ? '  [NEGATIVE CONTROL vs immutable pre-fix fixtures]' : '') + ' ===\n');

// ---------------------------------------------------------------------------
// FIX-0 — fixture integrity. Runs in BOTH modes so a rotten fixture is caught even
// on a normal run, when the fixtures are otherwise unused.
// ---------------------------------------------------------------------------
for (const [target, f] of Object.entries(FIXTURES)) {
  const fpath = path.join(ROOT, f.rel);
  let raw = null;
  try { raw = fs.readFileSync(fpath); } catch (_) {}
  ok(raw !== null, 'FIX-0a fixture present for ' + target + ' (' + f.rel + ')');
  if (!raw) continue;
  const got = crypto.createHash('sha256').update(raw).digest('hex');
  ok(got === f.sha, 'FIX-0a fixture SHA-256 matches pin for ' + target + ' (' + f.sha.slice(0, 12) + '...)');
  if (got !== f.sha) console.log('     fixture has been MODIFIED: got ' + got);
  ok(f.defect(raw.toString('utf8')),
    'FIX-0b fixture still exhibits the original defect for ' + target);
}

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

const fixtureBroken = failures.some(f => f.indexOf('FIX-0') === 0);

if (!BASE) {
  console.log('PASSED: ' + pass + '   FAILED: ' + fail);
  if (fail) { console.log('\nFAILURES:'); failures.forEach(f => console.log('  - ' + f)); }
  process.exit(fail ? 1 : 0);
}

// --- negative control mode -------------------------------------------------
const detected = failures.filter(f => f.indexOf('FIX-0') !== 0);
console.log('NEGATIVE CONTROL  assertions run: ' + (pass + fail) +
            '   defects detected: ' + detected.length +
            '   control integrity failures: ' + (fail - detected.length));

if (fixtureBroken) {
  console.log('\nCONTROL BROKEN — a pre-fix fixture is missing, modified, or no longer');
  console.log('exhibits its defect. This is NOT expected detection:');
  failures.filter(f => f.indexOf('FIX-0') === 0).forEach(f => console.log('  - ' + f));
  console.log('\nRESULT: FAIL (control cannot prove anything in this state)');
  process.exit(1);
}
if (detected.length === 0) {
  console.log('\nCONTROL INERT — ran against the pre-fix fixtures and detected NO defect.');
  console.log('Either the assertions no longer cover the chain-outcome corrections, or the');
  console.log('fixtures are not the pre-fix code. A control that detects nothing proves nothing.');
  console.log('\nRESULT: FAIL');
  process.exit(1);
}
if (detected.length < MIN_DETECTIONS) {
  console.log('\nCONTROL WEAKENED — detected ' + detected.length + ' defect(s) but expected at least ' +
              MIN_DETECTIONS + '.');
  console.log('Detection coverage has dropped. Either assertions that caught the over-claim');
  console.log('were removed or neutered, or the fixtures no longer exercise them. If the');
  console.log('assertion set changed on purpose, update MIN_DETECTIONS deliberately.');
  console.log('\nRESULT: FAIL');
  process.exit(1);
}
console.log('\nEXPECTED DETECTIONS (the control working correctly):');
detected.forEach(f => console.log('  - ' + f));
console.log('\nRESULT: PASS (' + detected.length + ' original defect(s) detected in the pre-fix fixtures)');
process.exit(0);
