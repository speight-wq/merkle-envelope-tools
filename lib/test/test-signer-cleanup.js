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

const ROOT = path.join(__dirname, '..');
const UNFIXED = process.argv.includes('--unfixed');

let pass = 0, fail = 0;
const failures = [];
function check(name, cond) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; failures.push(name); console.log('FAIL ' + name); }
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
  const html = (opts.source === 'HEAD')
    ? require('child_process').execSync('git show HEAD:signer.html', { cwd: ROOT, maxBuffer: 1 << 24 }).toString('utf8')
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

console.log('=== F-1 signer key-state cleanup' + (UNFIXED ? '  [NEGATIVE CONTROL: unfixed source]' : '') + ' ===\n');

// ---------------------------------------------------------------------------
// Negative control. Rather than textually reverting the fix (which only ever tests
// the reverter's regexes), --unfixed loads the ORIGINAL signer.html straight from
// git HEAD and runs this identical suite against it. If the suite does not fail
// there, the suite is not testing anything.
// ---------------------------------------------------------------------------
const loadOpts = UNFIXED ? { source: 'HEAD' } : {};

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
  const before = signAndCapture({ source: 'HEAD' });
  const after = signAndCapture({});
  check('EQ-1 signed transaction hex byte-identical to original', before.hex === after.hex && after.hex.length > 40);
  check('EQ-2 txid identical to original', before.txid === after.txid && /^[0-9a-f]{64}$/.test(after.txid));
  check('EQ-3 reported size identical', before.size === after.size);
  check('EQ-4 reported fee identical', before.fee === after.fee);
  console.log('   [EQ] signed tx = ' + (after.hex.length / 2) + ' bytes, txid ' + after.txid.slice(0, 16) + '...');
}

console.log('\n----------------------------------------');
console.log('PASSED: ' + pass + '   FAILED: ' + fail);
if (fail) { console.log('\nFAILURES:'); failures.forEach(f => console.log('  - ' + f)); }

if (UNFIXED) {
  console.log('\nNEGATIVE CONTROL: expected failures against the unfixed source.');
  process.exit(fail > 0 ? 0 : 1);   // control PASSES only if the suite FAILED
}
process.exit(fail ? 1 : 0);
