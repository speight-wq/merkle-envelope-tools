/*
 * test-signer-cleanup.js — F-1 regression suite: private-key state must be cleared
 * on EVERY exit path of the signing and build flows.
 *
 * Run: node test/test-signer-cleanup.js            (from the repo root)
 *      node test/test-signer-cleanup.js --unfixed  (negative control; MUST fail)
 *
 * Two defective paths are covered:
 *   Site A  createSignedTransaction() — historically called with no try/catch, so any
 *           throw between the key destructure and the tail cleanup left the key live
 *           in `pendingTx` and in the DOM input.
 *   Site B  the build handler's catch — historically rendered the error but never
 *           cleared `pendingTx`, so a DOM fault after the key was stored left it live.
 *
 * PROBE NOTE (load-bearing). `pendingTx` is declared with `let` inside the page's
 * IIFE. Two consequences drive this harness:
 *   1. The IIFE wrapper is stripped so the body runs at the vm context's top level;
 *      otherwise the binding is function-scoped and unobservable.
 *   2. The binding is then a context-level LEXICAL binding. It is NOT a property of
 *      the context object, so `ctx.pendingTx` reads `undefined` and any assertion
 *      written that way passes vacuously against broken code. It must be read with
 *      vm.runInContext('pendingTx === null', ctx). PROBE-0 below proves the probe
 *      can actually observe a non-null value, so a green run cannot be vacuous.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const UNFIXED = process.argv.includes('--unfixed');

// ---------------------------------------------------------------------------
// NEGATIVE-CONTROL BASELINE
//
// This control previously read the pre-fix source with `git show HEAD:signer.html`.
// Once the fix was committed, HEAD *contained* the fix, so the control compared the
// fix against itself, reported zero failures, and printed text that read like
// success. It was inert and nothing noticed.
//
// The baseline is now an immutable fixture: the exact pre-fix signer.html, taken
// verbatim from commit c0477870 (the last commit before F-1 landed). It is not a
// reconstruction and not a transformation of the current file — it is the original
// file, so it exhibits the original defect by being the original code.
//
// Two guards make fixture rot an explicit, diagnosable failure rather than a silent
// one:
//   FIX-0a  the fixture's SHA-256 is pinned below. Any edit fails immediately and
//           says so, instead of surfacing later as a confusing assertion failure.
//   FIX-0b  the fixture is checked to still EXHIBIT the defect (no clearKeyState,
//           and a bare createSignedTransaction() call with no error handling).
// If either guard fails, the suite fails. A control that detects nothing is a
// failing control, enforced at the bottom of this file.
//
// No network and no git history are required.
// ---------------------------------------------------------------------------
const FIXTURE_REL = 'test/fixtures/prefix-f1-signer.html';
const FIXTURE_SHA256 = 'c4a85cffc27bd3721959d357e4c0fc272756089b37beca0b7c47792497338933';

// Minimum number of assertions that MUST detect the defect in the pre-fix fixture.
// Requiring merely "at least one" is too weak: disabling 37 of 38 detections would
// still pass, so a collapse in detection coverage would go unnoticed. This is the
// count observed when the control was written. More is fine (a new assertion that also
// catches F-1); fewer fails loudly. If you intentionally change the assertion set,
// update this number in the same commit so the change is an explicit decision.
const MIN_DETECTIONS = 38;

let pass = 0, fail = 0;
const failures = [];
function check(name, cond) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else {
    fail++; failures.push(name);
    // Under --unfixed a failing assertion is the EXPECTED outcome: it is the control
    // detecting the original defect. Labelling it 'FAIL' would misread as a problem,
    // and would also look like a real failure to run-all.js's output scanner.
    // FIX-0* are control-integrity assertions and are genuine failures in both modes.
    const expected = UNFIXED && name.indexOf('FIX-0') !== 0;
    console.log((expected ? 'DETECT ' : 'FAIL ') + name);
  }
}

// ---------------------------------------------------------------------------
// DOM stub
// ---------------------------------------------------------------------------
function makeDom(opts) {
  opts = opts || {};
  const els = {};
  // Mutable so a test can remove nodes AFTER the script has initialised; removing
  // them before load would break the page's own top-level addEventListener calls.
  const missing = opts.missing ? opts.missing.slice() : [];
  // Nodes that EXIST but throw when written to. Models the reachable secondary
  // DOM fault: a missing node would instead throw at handler entry (signer.html
  // dereferences errorDiv before the try), before any key is stored.
  const throwOnSet = opts.throwOnSet ? opts.throwOnSet.slice() : [];
  function el(id) {
    if (missing.indexOf(id) !== -1) return null;
    if (!els[id]) {
      els[id] = {
        id: id, _tc: '', _html: '', _v: '', _cls: {}, dataset: {}, style: {}, disabled: false,
        addEventListener(ev, fn) { this['_on' + ev] = fn; },
        removeEventListener() {},
        classList: {
          add(c) { els[id]._cls[c] = true; },
          remove(c) {
            if (throwOnSet.indexOf(id) !== -1) throw new TypeError('simulated DOM fault on classList.remove for #' + id);
            delete els[id]._cls[c];
          },
          contains(c) { return !!els[id]._cls[c]; }
        },
        focus() {}, blur() {}, click() {}, appendChild() {}, removeChild() {},
        setAttribute() {}, getAttribute() { return null; },
        get value() { return this._v; }, set value(x) { this._v = x; },
        get textContent() { return this._tc; },
        set textContent(x) {
          if (throwOnSet.indexOf(id) !== -1) throw new TypeError('simulated DOM fault setting textContent on #' + id);
          this._tc = String(x);
        },
        get innerHTML() { return this._html; }, set innerHTML(x) { this._html = String(x); },
        set className(x) {}, set type(x) { this._type = x; }, get type() { return this._type; },
        get checked() { return !!this._checked; }, set checked(x) { this._checked = x; }
      };
    }
    return els[id];
  }
  const document = {
    getElementById: el,
    createElement() { return el('__created_' + Math.random()); },
    addEventListener() {}, body: el('__body')
  };
  return { document: document, els: els, missing: missing, throwOnSet: throwOnSet };
}

// ---------------------------------------------------------------------------
// Load signer.html's script body into a fresh context, IIFE wrapper stripped.
// `mutate` lets a case rewrite the source (used only by the negative control).
// ---------------------------------------------------------------------------
function loadSigner(opts) {
  opts = opts || {};
  const html = (opts.source === 'PREFIX')
    ? fs.readFileSync(path.join(ROOT, FIXTURE_REL), 'utf8')
    : fs.readFileSync(path.join(ROOT, 'signer.html'), 'utf8');
  const open = html.indexOf('<script>');
  const close = html.indexOf('</script>', open);
  if (open < 0 || close < 0) throw new Error('could not locate inline <script> in signer.html');
  let body = html.slice(open + '<script>'.length, close);

  // Strip the IIFE wrapper so `let pendingTx` lands in the context's top-level
  // lexical scope and becomes observable (see PROBE NOTE).
  const iifeStart = body.indexOf('(function() {');
  const iifeEnd = body.lastIndexOf('})();');
  if (iifeStart < 0 || iifeEnd < 0) throw new Error('could not locate signer IIFE');
  body = body.slice(iifeStart + '(function() {'.length, iifeEnd);

  const dom = makeDom(opts);
  const ctx = {
    document: dom.document,
    addEventListener() {}, removeEventListener() {},
    navigator: { onLine: false, clipboard: { writeText() { return Promise.resolve(); } } },
    setTimeout() { return 0; }, clearTimeout() {},
    Blob: function () {}, URL: { createObjectURL() { return 'blob:x'; }, revokeObjectURL() {} },
    console: { log() {}, warn() {}, error() {} },
    Date: Date, Math: Math, JSON: JSON, BigInt: BigInt, Number: Number, String: String,
    Object: Object, Array: Array, Error: Error, TypeError: TypeError, RegExp: RegExp,
    Uint8Array: Uint8Array, DataView: DataView, ArrayBuffer: ArrayBuffer,
    isNaN: isNaN, parseInt: parseInt, parseFloat: parseFloat, TextEncoder: TextEncoder
  };
  // In a real browser `window` IS the global object, so lib/*.js attach their
  // exports to it. A separate stub object would silently divert every export
  // (isValidHex, hash256, SECP256K1, ...) out of the script's scope.
  ctx.global = ctx; ctx.globalThis = ctx; ctx.self = ctx; ctx.window = ctx;
  vm.createContext(ctx);
  for (const f of ['crypto.js', 'encoding.js', 'secp256k1.js', 'sighash.js', 'headers.js'])
    vm.runInContext(fs.readFileSync(path.join(ROOT, 'lib', f), 'utf8'), ctx);
  vm.runInContext(body, ctx);
  return { ctx: ctx, els: dom.els, missing: dom.missing, throwOnSet: dom.throwOnSet };
}

// Read the lexical binding. Never use ctx.pendingTx — it is not a context property.
function pendingIsNull(ctx) { return vm.runInContext('pendingTx === null', ctx) === true; }
function pendingHasKey(ctx) {
  return vm.runInContext('(pendingTx && typeof pendingTx.privateKey === "string" && pendingTx.privateKey.length > 0) === true', ctx) === true;
}

// ---------------------------------------------------------------------------
// Fixture: a real WIF + matching envelope, so the build path reaches :855.
// ---------------------------------------------------------------------------
function buildFixture() {
  // Load the libs into Node's own global (as the other suites do) purely to build
  // the fixture. The code under test runs in an isolated vm context, not here.
  for (const f of ['crypto.js', 'encoding.js', 'secp256k1.js', 'sighash.js'])
    require(path.join(ROOT, 'lib', f));
  const s = global;
  const privHex = '1'.repeat(63) + '7';
  const wif = s.base58CheckEncode(0x80, privHex + '01');
  const pub = s.SECP256K1.getPublicKey(privHex, true);
  const pkh = s.bytesToHex(s.hash160(pub));
  const addr = s.base58CheckEncode(0x00, pkh);
  // minimal 1-in/1-out tx paying pkh, so the envelope's vout 0 is spendable by this key
  const rawTx = '01000000' + '01' + '00'.repeat(32) + 'ffffffff' + '00' + 'ffffffff' +
                '01' + s.writeUInt64LE(100000) + '19' + '76a914' + pkh + '88ac' + '00000000';
  const txid = s.reverseHex(s.bytesToHex(s.hash256(rawTx)));
  return { wif: wif, privHex: privHex, address: addr,
           envelope: { txid: txid, vout: 0, satoshis: 100000, rawTx: rawTx } };
}
const FIX = buildFixture();

// Drive: paste envelope -> load -> enter WIF -> build -> confirm -> sign.
function driveToConfirm(h) {
  const { ctx, els } = h;
  ctx.document.getElementById('envelope-input').value = JSON.stringify([FIX.envelope]);
  els['parse-btn']._onclick.call(els['parse-btn']);
  ctx.document.getElementById('private-key').value = FIX.wif;
  els['private-key']._oninput && els['private-key']._oninput.call(els['private-key']);
  ctx.document.getElementById('dest-address').value = FIX.address;
  ctx.document.getElementById('amount').value = '0.0005';
  ctx.document.getElementById('address-verified').checked = true;
  ctx.document.getElementById('fee-rate') && (ctx.document.getElementById('fee-rate').value = '1');
  els['sign-btn']._onclick.call(els['sign-btn']);
}
function clickConfirmSign(h) {
  const { els } = h;
  els['confirm-sign'].disabled = false;
  els['confirm-sign']._onclick.call(els['confirm-sign']);
}

console.log('=== F-1 signer key-state cleanup' +
  (UNFIXED ? '  [NEGATIVE CONTROL vs immutable pre-fix fixture]' : '') + ' ===\n');

// ---------------------------------------------------------------------------
// FIX-0 — fixture integrity. Runs in BOTH modes: the fixed run uses the fixture for
// the EQ byte-equivalence comparison, so a rotten fixture must be caught either way.
// ---------------------------------------------------------------------------
{
  const fpath = path.join(ROOT, FIXTURE_REL);
  let raw = null;
  try { raw = fs.readFileSync(fpath); } catch (_) {}
  check('FIX-0a pre-fix fixture present at ' + FIXTURE_REL, raw !== null);
  if (raw) {
    const got = crypto.createHash('sha256').update(raw).digest('hex');
    check('FIX-0a fixture SHA-256 matches the pin (' + FIXTURE_SHA256.slice(0, 12) + '...)',
      got === FIXTURE_SHA256);
    if (got !== FIXTURE_SHA256) console.log('     fixture has been MODIFIED: got ' + got);
    const txt = raw.toString('utf8');
    // The fixture must still exhibit the ORIGINAL defect, or the control is vacuous.
    check('FIX-0b fixture exhibits the defect: no clearKeyState',
      txt.indexOf('clearKeyState') === -1);
    check('FIX-0b fixture exhibits the defect: createSignedTransaction() called unguarded',
      /\n\s*createSignedTransaction\(\);/.test(txt));
  }
}

// ---------------------------------------------------------------------------
// Negative control. Rather than textually reverting the fix (which only ever tests
// the reverter's regexes), --unfixed loads the ORIGINAL signer.html straight from
// git HEAD and runs this identical suite against it. If the suite does not fail
// there, the suite is not testing anything.
// ---------------------------------------------------------------------------
const loadOpts = UNFIXED ? { source: 'PREFIX' } : {};

// ---------------------------------------------------------------------------
// PROBE-0 — prove the probe is not vacuous
// ---------------------------------------------------------------------------
{
  const h = loadSigner(loadOpts);
  check('PROBE-0a probe reads null on a fresh page', pendingIsNull(h.ctx));
  vm.runInContext('pendingTx = { privateKey: "deadbeef" };', h.ctx);
  check('PROBE-0b probe DETECTS a deliberately non-null pendingTx', pendingIsNull(h.ctx) === false);
  check('PROBE-0c probe sees the key material inside it', pendingHasKey(h.ctx) === true);
  vm.runInContext('pendingTx = null;', h.ctx);
  check('PROBE-0d probe returns to null', pendingIsNull(h.ctx));
}

// ---------------------------------------------------------------------------
// BASELINE — the happy path must be unchanged
// ---------------------------------------------------------------------------
{
  const h = loadSigner(loadOpts);
  driveToConfirm(h);
  if (!pendingHasKey(h.ctx)) {
    for (const id of ['tx-error','envelope-error','key-info','parse-error','error'])
      if (h.els[id]) console.log('   [diag] #' + id + ' = ' + JSON.stringify(String(h.els[id].textContent||'').slice(0,160)));
    console.log('   [diag] verifiedInputs len = ' + vm.runInContext('(typeof verifiedInputs!=="undefined")?verifiedInputs.length:"undef"', h.ctx));
  }
  check('BASE-1 build populated pendingTx with the key', pendingHasKey(h.ctx));
  clickConfirmSign(h);
  check('BASE-2 success: pendingTx cleared', pendingIsNull(h.ctx));
  check('BASE-3 success: WIF input cleared', h.els['private-key'].value === '');
  check('BASE-4 success: raw tx produced', /^[0-9a-f]{20,}$/.test(h.els['result-hex'].value || ''));
  check('BASE-5 success: txid displayed', /^[0-9a-f]{64}$/.test(h.els['result-txid'].textContent || ''));
  check('BASE-6 success: result panel shown', h.els['tx-result'].classList.contains('hidden') === false);
}

// ---------------------------------------------------------------------------
// SITE A — exceptions during signing
// ---------------------------------------------------------------------------
function siteA(name, inject, expectErrSubstr) {
  const h = loadSigner(loadOpts);
  driveToConfirm(h);
  if (!pendingHasKey(h.ctx)) { check(name + ' [precondition: key held]', false); return; }
  vm.runInContext(inject, h.ctx);
  let threw = false;
  try { clickConfirmSign(h); } catch (e) { threw = true; }
  check(name + ' -> pendingTx cleared', pendingIsNull(h.ctx));
  check(name + ' -> WIF input cleared', h.els['private-key'].value === '');
  check(name + ' -> no key hex left in pendingTx', pendingHasKey(h.ctx) === false);
  check(name + ' -> exception did not escape the handler', threw === false);
  const errText = (h.els['tx-error'] && h.els['tx-error'].textContent) || '';
  check(name + ' -> visible error shown', errText.length > 0 && /Signing failed/i.test(errText));
  if (expectErrSubstr) check(name + ' -> error preserves the original cause',
    errText.indexOf(expectErrSubstr) !== -1);
}

siteA('A1 SECP256K1.sign throws (r=0)',
  'SECP256K1.sign = function(){ throw new Error("Invalid signature (r=0)"); };',
  'Invalid signature (r=0)');
siteA('A2 self-verification fails',
  'SECP256K1.verify = function(){ return false; };',
  'Signature self-verification failed');
siteA('A3 signatureToDER throws',
  'SECP256K1.signatureToDER = function(){ throw new Error("DER encode fault"); };',
  'DER encode fault');
siteA('A4 sighash computation throws',
  'computeSighash = function(){ throw new Error("sighash fault"); };',
  'sighash fault');

// A5: a DOM write in the result panel throws (element missing).
{
  const h = loadSigner(Object.assign({}, loadOpts, { missing: ['result-txid'] }));
  driveToConfirm(h);
  const held = pendingHasKey(h.ctx);
  let threw = false;
  try { clickConfirmSign(h); } catch (e) { threw = true; }
  check('A5 missing result DOM node [precondition: key held]', held);
  check('A5 missing result DOM node -> pendingTx cleared', pendingIsNull(h.ctx));
  check('A5 missing result DOM node -> exception did not escape', threw === false);
}

// A6: clearKeyState must not throw even when every DOM node is missing.
{
  const h = loadSigner(loadOpts);
  h.missing.push('private-key', 'key-info', 'tx-error');   // remove AFTER init
  let threw = false;
  try { vm.runInContext('pendingTx = { privateKey: "dead" }; clearKeyState();', h.ctx); }
  catch (e) { threw = true; }
  check('A6 clearKeyState survives all DOM nodes missing', threw === false);
  check('A6 clearKeyState still nulled pendingTx', pendingIsNull(h.ctx));
}

// ---------------------------------------------------------------------------
// SITE B — exceptions during build, after the key is stored
// ---------------------------------------------------------------------------
function siteB(name, missingId) {
  const h = loadSigner(Object.assign({}, loadOpts, { missing: [missingId] }));
  let threw = false;
  try { driveToConfirm(h); } catch (e) { threw = true; }
  check(name + ' -> pendingTx cleared', pendingIsNull(h.ctx));
  check(name + ' -> no key hex retained', pendingHasKey(h.ctx) === false);
  check(name + ' -> exception did not escape', threw === false);
  // Agreed behaviour: the WIF field is deliberately RETAINED for the retry workflow.
  check(name + ' -> WIF retained for retry', h.els['private-key'].value === FIX.wif);
}
siteB('B1 confirm-to node missing', 'confirm-to');
siteB('B2 confirm-amount node missing', 'confirm-amount');
siteB('B3 confirm-modal node missing', 'confirm-modal');

// B4 — the error-display node itself fails while the catch is rendering.
// Cleanup must already have happened (it runs first), the secondary fault must not
// escape, and the WIF must still be available for retry.
//
// Reachability note: making #tx-error *absent* would not exercise this path at all —
// signer.html dereferences errorDiv at handler entry, BEFORE the try and before any
// key is stored, so nothing would be left to leak. The reachable form is a node that
// exists at entry but throws while being written to, which is what is simulated here.
{
  const h = loadSigner(loadOpts);
  // force a build failure after the key is stored...
  h.missing.push('confirm-to');
  // ...and make the error-rendering itself fail too.
  h.throwOnSet.push('tx-error');
  let threw = false, escaped = null;
  try { driveToConfirm(h); } catch (e) { threw = true; escaped = e; }
  check('B4 error-render fault -> pendingTx still cleared', pendingIsNull(h.ctx));
  check('B4 error-render fault -> no key hex retained', pendingHasKey(h.ctx) === false);
  check('B4 error-render fault -> nothing escaped as an unhandled exception',
    threw === false && escaped === null);
  check('B4 error-render fault -> WIF retained for retry', h.els['private-key'].value === FIX.wif);
  check('B4 error-render fault -> cleanup succeeded despite render failure',
    pendingIsNull(h.ctx) && h.els['private-key'].value === FIX.wif);
}

// ---------------------------------------------------------------------------
// CANCEL path
// ---------------------------------------------------------------------------
{
  const h = loadSigner(loadOpts);
  driveToConfirm(h);
  check('C1 cancel [precondition: key held]', pendingHasKey(h.ctx));
  h.els['confirm-cancel']._onclick.call(h.els['confirm-cancel']);
  check('C1 cancel -> pendingTx cleared', pendingIsNull(h.ctx));
  check('C1 cancel -> WIF retained for retry', h.els['private-key'].value === FIX.wif);
}

// ---------------------------------------------------------------------------
// LEAK SCAN — key material must not reach any visible surface
// ---------------------------------------------------------------------------
{
  const h = loadSigner(loadOpts);
  driveToConfirm(h);
  vm.runInContext('SECP256K1.sign = function(){ throw new Error("boom"); };', h.ctx);
  try { clickConfirmSign(h); } catch (e) {}
  let leaked = false;
  for (const id of Object.keys(h.els)) {
    const e = h.els[id];
    for (const v of [e._tc, e._html, id === 'private-key' ? '' : e._v]) {
      if (typeof v === 'string' && v && (v.indexOf(FIX.privHex) !== -1 || v.indexOf(FIX.wif) !== -1)) {
        leaked = true; console.log('   leak in #' + id + ': ' + v.slice(0, 60));
      }
    }
  }
  check('L1 no WIF or private-key hex on any visible surface after failure', leaked === false);
}

// ---------------------------------------------------------------------------
// EQ — successful signing must be byte-identical to the original implementation.
// Runs the same inputs through signer.html at git HEAD and through the working
// tree, and compares the produced transaction. Skipped under --unfixed (both
// sides would be the same file).
// ---------------------------------------------------------------------------
if (!UNFIXED) {
  function signAndCapture(opts) {
    const h = loadSigner(opts);
    driveToConfirm(h);
    clickConfirmSign(h);
    return {
      hex: h.els['result-hex'].value,
      txid: h.els['result-txid'].textContent,
      size: h.els['result-size'].textContent,
      fee: h.els['result-fee'].textContent
    };
  }
  const before = signAndCapture({ source: 'PREFIX' });
  const after = signAndCapture({});
  check('EQ-1 signed transaction hex byte-identical to original', before.hex === after.hex && after.hex.length > 40);
  check('EQ-2 txid identical to original', before.txid === after.txid && /^[0-9a-f]{64}$/.test(after.txid));
  check('EQ-3 reported size identical', before.size === after.size);
  check('EQ-4 reported fee identical', before.fee === after.fee);
  console.log('   [EQ] signed tx = ' + (after.hex.length / 2) + ' bytes, txid ' + after.txid.slice(0, 16) + '...');
}

console.log('\n----------------------------------------');

// ---------------------------------------------------------------------------
// Outcome reporting. The two modes mean opposite things, so they are labelled
// differently: under --unfixed a non-zero failure count is the SUCCESS condition.
// Fixture-integrity failures (FIX-0*) are never "expected detection" — they mean the
// control itself is broken, so they are called out separately.
// ---------------------------------------------------------------------------
const fixtureBroken = failures.some(f => f.indexOf('FIX-0') === 0);

if (!UNFIXED) {
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
  console.log('\nCONTROL BROKEN — the pre-fix fixture is missing, modified, or no longer');
  console.log('exhibits the defect. This is NOT expected detection:');
  failures.filter(f => f.indexOf('FIX-0') === 0).forEach(f => console.log('  - ' + f));
  console.log('\nRESULT: FAIL (control cannot prove anything in this state)');
  process.exit(1);
}
if (detected.length === 0) {
  console.log('\nCONTROL INERT — ran against the pre-fix fixture and detected NO defect.');
  console.log('Either the assertions no longer cover F-1, or the fixture is not the');
  console.log('pre-fix code. A control that detects nothing proves nothing.');
  console.log('\nRESULT: FAIL');
  process.exit(1);
}
if (detected.length < MIN_DETECTIONS) {
  console.log('\nCONTROL WEAKENED — detected ' + detected.length + ' defect(s) but expected at least ' +
              MIN_DETECTIONS + '.');
  console.log('Detection coverage has dropped. Either assertions that caught F-1 were');
  console.log('removed or neutered, or the fixture no longer exercises them. If the');
  console.log('assertion set changed on purpose, update MIN_DETECTIONS deliberately.');
  console.log('\nRESULT: FAIL');
  process.exit(1);
}
console.log('\nEXPECTED DETECTIONS (the control working correctly):');
detected.forEach(f => console.log('  - ' + f));
console.log('\nRESULT: PASS (' + detected.length + ' original F-1 defect(s) detected in the pre-fix fixture)');
process.exit(0);
