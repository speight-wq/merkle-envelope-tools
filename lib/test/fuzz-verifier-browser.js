'use strict';
/*
 * test/fuzz-verifier-browser.js - deterministic, seed-logged fuzzing of the SHIPPED verifier.html
 * verification path.
 *
 * Unlike explorer.html (legacy-proof, no rawTx bind), verifier.html is DOM-driven, prefers
 * BUMP > BEEF > legacy proof, and binds rawTx (txid == SHA256d(rawTx)). This harness runs the
 * shipped verifier click-handler UNCHANGED in a vm with the real lib/*.js loaded and a minimal
 * DOM stub, then reads the typed outcome the verifier writes (data-outcome / title). Observer-
 * only: no production file is modified.
 *
 * Determinism: the timestamp policy reads Date.now(); a FIXED clock (corpus header + 1yr) is
 * injected into the vm (test-only, isolated here). presentation is ignored.
 *
 * Invariants: A no uncaught exception escaping the handler; B no VERIFIED/VERIFIED-ISOLATION
 * unless txid==SHA256d(rawTx) AND the txid->root->header binding holds (recomputed independently
 * via the verifier's own priority: BUMP else legacy) AND chain membership for VERIFIED; C a
 * documented typed outcome; D determinism; E differential vs the independent verifier
 * (bump-preferring, rawTx-binding) - accept/reject mismatch is hard, reject-class difference is
 * recorded. BEEF root reconstruction is NOT independently covered (no independent BEEF parser);
 * for BEEF-path acceptances only the rawTx binding is independently checked - documented below.
 *
 * Run:
 *   node test/fuzz-verifier-browser.js --seed 20260401 --iters 20000
 *   node test/fuzz-verifier-browser.js --seed 20260401 --replay 4242
 *   node test/fuzz-verifier-browser.js --seed 20260401 --iters 20000 --negative-control
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const IND = require(path.join(ROOT, 'headers-node-independent/verify.js'));
// lib crypto/encoding are loaded here ONLY for the rawTx->txid binding recompute, so the oracle
// decodes rawTx hex the same lenient way the shipped verifier does (Node's Buffer.from truncates
// at the first non-hex char, which would spuriously flag semantics-preserving mutations whose
// lib-decoded bytes still hash to the txid). The Merkle/proof oracle below stays independent
// (rootFromBump / rootFromLegacy from headers-node-independent).
require(path.join(ROOT, 'lib/crypto.js'));
require(path.join(ROOT, 'lib/encoding.js'));
const LIBHASH = global.hash256, LIBHEX = global.bytesToHex, LIBREV = global.reverseHex;
const ENV = JSON.parse(fs.readFileSync(path.join(ROOT, 'test/real-envelope.json'), 'utf8'));
const HEADER_TS = Buffer.from(ENV.blockHeader, 'hex').readUInt32LE(68);
const FIXED_CLOCK_MS = (HEADER_TS + 31536000) * 1000; // corpus header + 1yr, deterministic
const CORPUS_BLOCKHASH = IND.headerHashDisplay(ENV.blockHeader).toLowerCase();

// ---- extract the shipped verifier.html IIFE + run it against a DOM stub -------------------
const VERIFIER_HTML = fs.readFileSync(path.join(ROOT, 'verifier.html'), 'utf8');
const IIFE_START = VERIFIER_HTML.indexOf('(function() {');
const IIFE_END = VERIFIER_HTML.indexOf('})();', IIFE_START) + 5;
const VERIFIER_SCRIPT = VERIFIER_HTML.slice(IIFE_START, IIFE_END);

function makeDomCtx() {
  const els = {};
  const el = (id) => (els[id] || (els[id] = {
    _v: '', _tc: '', _attrs: {}, _ds: {},
    addEventListener(ev, fn) { this['_' + ev] = fn; },
    classList: { add() {}, remove() {} },
    get value() { return this._v; }, set value(x) { this._v = x; },
    set textContent(x) { this._tc = x; }, get textContent() { return this._tc; },
    set className(x) {}, set innerHTML(x) {},
    setAttribute(k, v) { this._attrs[k] = v; }, getAttribute(k) { return this._attrs[k]; },
    get dataset() { return this._ds; }
  }));
  return { els, document: { getElementById: el } };
}
// one shared vm context with the REAL libs + fixed clock; reused across iterations
function buildContext() {
  const { els, document } = makeDomCtx();
  const ctx = {};
  ctx.global = ctx; ctx.document = document; ctx.performance = { now: () => 0 };
  ctx.TextEncoder = TextEncoder; ctx.console = { log() {}, warn() {}, error() {} };
  const FIXED = FIXED_CLOCK_MS;
  ctx.Date = class extends Date { constructor(...a) { if (a.length) super(...a); else super(FIXED); } static now() { return FIXED; } };
  vm.createContext(ctx);
  for (const f of ['crypto.js', 'encoding.js', 'headers.js', 'bump.js', 'beef.js']) vm.runInContext(fs.readFileSync(path.join(ROOT, 'lib', f), 'utf8'), ctx);
  // lib/bump.js and lib/beef.js are CommonJS modules; expose their exports as globals the page expects
  vm.runInContext("var module={};", ctx); // guard; the files are IIFE-guarded already in-page context
  vm.runInContext(VERIFIER_SCRIPT, ctx);
  return { ctx, els };
}
let ENVCTX = null;
function shippedVerify(env, chainHashIndex) {
  if (!ENVCTX) ENVCTX = buildContext();
  const { ctx, els } = ENVCTX;
  ctx.chainHashIndex = chainHashIndex || null;
  ctx.chainLoadFailed = false;
  // fresh result elements each run
  for (const id of ['result-box', 'result-title', 'checks', 'details', 'result-section']) { delete els[id]; ctx.document.getElementById(id); }
  ctx.document.getElementById('envelope-input').value = typeof env === 'string' ? env : JSON.stringify(env);
  ctx.document.getElementById('verify-btn')._click(); // may throw -> Invariant A
  const rt = els['result-title'];
  const outcome = (rt && (rt._attrs['data-outcome'] || rt._ds.outcome)) || null;
  return { outcome, title: rt ? rt._tc : null };
}

// ---- PRNG + mutation catalogue (shared style with fuzz-browser.js) -----------------------
function mulberry32(a) { return function () { a |= 0; a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
function iterationRng(seed, i) { return mulberry32(((seed >>> 0) ^ Math.imul(i + 1, 2654435761)) >>> 0); }
const pick = (rng, a) => a[Math.floor(rng() * a.length)];
const randInt = (rng, n) => Math.floor(rng() * n);
const randByte = (rng) => Math.floor(rng() * 256);
const toHex = (b) => Buffer.from(b).toString('hex');
const fromHex = (h) => Buffer.from(h, 'hex');
const sha256d = (b) => crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest();

function mutateHexField(rng, hex) {
  const ops = ['flip', 'truncate', 'extend', 'zero-range', 'non-hex', 'odd-length', 'empty', 'dup-region', 'non-hex-64'];
  const op = pick(rng, ops);
  if (op === 'empty') return { op, hex: '' };
  if (op === 'odd-length') return { op, hex: (hex.length ? hex.slice(0, hex.length - 1) : 'a') };
  if (op === 'non-hex') { const at = randInt(rng, hex.length || 1); return { op, hex: hex.slice(0, at) + 'g' + hex.slice(at + 1) }; }
  if (op === 'non-hex-64') return { op, hex: 'g'.repeat(64) };
  const b = fromHex(hex.length % 2 ? hex + '0' : hex);
  if (op === 'truncate') { const at = randInt(rng, b.length + 1); return { op, hex: toHex(b.subarray(0, at)) }; }
  if (op === 'extend') { const n = 1 + randInt(rng, 8); return { op, hex: toHex(Buffer.concat([b, Buffer.from(Array.from({ length: n }, () => randByte(rng)))])) }; }
  if (op === 'flip') { if (b.length) b[randInt(rng, b.length)] ^= (1 << randInt(rng, 8)); return { op, hex: toHex(b) }; }
  if (op === 'zero-range') { if (b.length) { const a = randInt(rng, b.length); for (let i = a; i < Math.min(b.length, a + 1 + randInt(rng, 32)); i++) b[i] = 0; } return { op, hex: toHex(b) }; }
  if (b.length > 4) { const a = randInt(rng, b.length - 2); const len = 1 + randInt(rng, Math.min(16, b.length - a)); return { op, hex: toHex(Buffer.concat([b.subarray(0, a), b.subarray(a, a + len), b.subarray(a)])) }; }
  return { op, hex };
}

// verifier's verdict inputs: bump (preferred) / beef / legacy proof / header / txid / rawTx + type confusion
function mutateEnvelope(rng) {
  const env = JSON.parse(JSON.stringify(ENV));
  const strat = pick(rng, [
    'bump', 'bump', 'bump', 'proof', 'proof', 'header', 'header', 'txid', 'rawTx', 'rawTx',
    'drop-bump', 'drop-proof', 'drop-header', 'drop-txid', 'drop-rawTx',
    'empty-field', 'type-confuse', 'wrong-txid', 'proof-pos', 'extra-field'
  ]);
  let mutation = strat, params = {};
  if (strat === 'bump') { const m = mutateHexField(rng, env.bump); env.bump = m.hex; mutation = 'bump:' + m.op; }
  else if (strat === 'proof') { delete env.bump; if (env.proof && env.proof.length) { const i = randInt(rng, env.proof.length); const m = mutateHexField(rng, env.proof[i].hash); env.proof[i].hash = m.hex; mutation = 'proof.hash:' + m.op; params = { i }; } }
  else if (strat === 'proof-pos') { delete env.bump; if (env.proof && env.proof.length) { const i = randInt(rng, env.proof.length); env.proof[i].pos = pick(rng, ['L', 'R', 'l', 'X', '', null]); mutation = 'proof.pos'; params = { i, pos: env.proof[i].pos }; } }
  else if (strat === 'header') { const m = mutateHexField(rng, env.blockHeader); env.blockHeader = m.hex; mutation = 'header:' + m.op; }
  else if (strat === 'txid') { const m = mutateHexField(rng, env.txid); env.txid = m.hex; mutation = 'txid:' + m.op; }
  else if (strat === 'wrong-txid') { env.txid = 'ab'.repeat(32); mutation = 'txid:wrong'; }
  else if (strat === 'rawTx') { const m = mutateHexField(rng, env.rawTx); env.rawTx = m.hex; mutation = 'rawTx:' + m.op; }
  else if (strat === 'drop-bump') { delete env.bump; mutation = 'drop-bump'; }
  else if (strat === 'drop-proof') { delete env.proof; mutation = 'drop-proof'; }
  else if (strat === 'drop-header') { delete env.blockHeader; mutation = 'drop-header'; }
  else if (strat === 'drop-txid') { delete env.txid; mutation = 'drop-txid'; }
  else if (strat === 'drop-rawTx') { delete env.rawTx; mutation = 'drop-rawTx'; }
  else if (strat === 'empty-field') { const f = pick(rng, ['bump', 'blockHeader', 'txid', 'rawTx']); env[f] = ''; mutation = 'empty:' + f; }
  else if (strat === 'type-confuse') { const f = pick(rng, ['txid', 'blockHeader', 'bump', 'proof', 'rawTx']); env[f] = pick(rng, [null, 123, true, {}, [], [1, 2]]); mutation = 'type-confuse:' + f; }
  else if (strat === 'extra-field') { env['__x' + randInt(rng, 9)] = 'junk'; mutation = 'extra-field'; }
  return { env, mutation, params };
}

function chainState(rng) {
  const k = randInt(rng, 3);
  if (k === 0) return { name: 'no-chain', index: null };
  if (k === 1) return { name: 'chain-has', index: new Map([[CORPUS_BLOCKHASH, 935023]]) };
  return { name: 'chain-lacks', index: new Map([['00'.repeat(32), 1]]) };
}

// ---- independent oracle for Invariant B (verifier priority: BUMP else legacy; binds rawTx) --
const DOCUMENTED = new Set(['VERIFIED', 'VERIFIED-ISOLATION', 'FAILED', 'POLICY-REJECTED', 'MALFORMED', 'INDETERMINATE', 'NOT-ESTABLISHED']);
const ACCEPT = new Set(['VERIFIED', 'VERIFIED-ISOLATION']);
function rawTxBinds(env) {
  try { if (typeof env.rawTx !== 'string') return false; return LIBREV(LIBHEX(LIBHASH(env.rawTx))).toLowerCase() === String(env.txid).toLowerCase(); } catch (_) { return false; }
}
function bindingHolds(env) {
  try {
    if (typeof env.blockHeader !== 'string' || env.blockHeader.length !== 160) return { ok: false };
    if (typeof env.txid !== 'string' || env.txid.length !== 64) return { ok: false };
    if (!rawTxBinds(env)) return { ok: false, reason: 'rawTx' };
    const hdr = IND.parseHeader(env.blockHeader);
    // match verifier truthiness: empty-string bump/beef are falsy -> fall back to legacy proof
    if (env.bump) {
      const root = IND.rootFromBump(IND.parseBump(env.bump), env.txid);
      return { ok: root.toLowerCase() === hdr.merkleRootField.toLowerCase() };
    }
    if (env.beef || env.atomicBeef) return { ok: true, beef: true }; // not independently covered
    const root = IND.rootFromLegacy(env.txid, env.proof || []);
    return { ok: root.toLowerCase() === hdr.merkleRootField.toLowerCase() };
  } catch (_) { return { ok: false }; }
}

function runIteration(seed, i, opts) {
  opts = opts || {};
  const rng = iterationRng(seed, i);
  const { env, mutation, params } = mutateEnvelope(rng);
  const cs = chainState(rng);
  const rec = { seed, iter: i, mutation, params, chain: cs.name };
  const viol = [];

  let out = null, threw = null;
  try {
    const r = shippedVerify(env, cs.index);
    out = r.outcome;
    if (opts.simulateFalseVerified) out = 'VERIFIED'; // negative control
  } catch (e) { threw = (e && e.message) || String(e); viol.push('A: shipped verifier threw uncaught (' + threw + ')'); }
  rec.shipped = threw ? ('throw:' + threw) : out;

  if (out != null) {
    if (!DOCUMENTED.has(out)) viol.push('C: undocumented outcome ' + out);
    if (ACCEPT.has(out)) {
      const b = bindingHolds(env);
      if (b.beef) rec.beefNote = 'BEEF path: rawTx binding checked; BEEF->root not independently covered';
      else if (!b.ok) viol.push('B: shipped ' + out + ' but binding does not hold (' + (b.reason || 'root') + ')');
      if (out === 'VERIFIED' && cs.name !== 'chain-has') viol.push('B: shipped VERIFIED without block in loaded chain (' + cs.name + ')');
    }
  }

  // Invariant E: differential vs independent verifier (bump-preferring, binds rawTx like verifier)
  let indOut = null;
  try { indOut = IND.verify(env, { bindRawTx: true, chainHashIndex: cs.index, trustIndex: true }).outcome; } catch (_) { indOut = 'THREW'; }
  rec.independent = indOut;
  if (out != null && indOut && indOut !== 'THREW' && out !== indOut) {
    const shipAccept = ACCEPT.has(out), indAccept = ACCEPT.has(indOut);
    if (shipAccept !== indAccept) {
      const b = bindingHolds(env);
      if (shipAccept && !b.ok && !b.beef) viol.push('DIFF-HARD: shipped ' + out + ' accepted w/o binding; independent ' + indOut);
      else rec.knownDivergence = 'shipped=' + out + ' independent=' + indOut + ' (accept/reject differ; binding ' + (b.ok ? 'holds' : 'n/a') + ')';
    } else {
      rec.knownDivergence = 'both reject, class differs (shipped=' + out + ' ind=' + indOut + ')';
    }
  }
  return { rec, viol };
}

// ---- CLI ---------------------------------------------------------------------------------
function arg(name, def) { const k = process.argv.indexOf(name); return k >= 0 && process.argv[k + 1] != null ? process.argv[k + 1] : def; }
const seed = (parseInt(arg('--seed', '' + ((Date.now() ^ (process.pid << 8)) >>> 0)), 10) >>> 0);
const iters = parseInt(arg('--iters', '1000'), 10);
const replay = process.argv.indexOf('--replay') >= 0 ? parseInt(arg('--replay', '0'), 10) : null;
const negControl = process.argv.indexOf('--negative-control') >= 0;

if (replay != null) {
  const a = runIteration(seed, replay);
  const b = runIteration(seed, replay);
  console.log('REPLAY seed=' + seed + ' iteration=' + replay);
  console.log(JSON.stringify(a.rec, null, 2));
  console.log('violations:', a.viol.length ? a.viol : 'none');
  console.log('deterministic:', JSON.stringify(a.rec) === JSON.stringify(b.rec));
  process.exit(a.viol.length ? 1 : 0);
}

console.log('Merkle Envelope Tools - shipped HTML verify() fuzz (verifier.html)\n');
console.log('Seed:       ' + seed);
console.log('Iterations: ' + iters);
console.log('Fixed clock:' + new Date(FIXED_CLOCK_MS).toISOString() + ' (corpus header + 1yr; test-only)');
if (negControl) console.log('MODE:       NEGATIVE CONTROL (planted false-VERIFIED in adapter)');
console.log('');

const mutClasses = {};
let exceptions = 0, falseAccepts = 0, typedViol = 0, hardDiv = 0, knownDiv = 0, nondet = 0;
const failures = [];
for (let i = 0; i < iters; i++) {
  let res;
  try { res = runIteration(seed, i, { simulateFalseVerified: negControl }); }
  catch (e) { exceptions++; failures.push({ seed, iter: i, fatal: String(e && e.stack || e) }); continue; }
  const cls = res.rec.mutation.split(':')[0];
  mutClasses[cls] = (mutClasses[cls] || 0) + 1;
  const res2 = runIteration(seed, i, { simulateFalseVerified: negControl });
  if (JSON.stringify(res.rec) !== JSON.stringify(res2.rec)) { nondet++; res.viol.push('D: non-deterministic'); }
  if (res.rec.knownDivergence) knownDiv++;
  for (const v of res.viol) {
    if (v.startsWith('A:')) exceptions++;
    else if (v.startsWith('B:')) falseAccepts++;
    else if (v.startsWith('C:')) typedViol++;
    else if (v.startsWith('DIFF-HARD:')) hardDiv++;
  }
  if (res.viol.length) failures.push({ ...res.rec, violations: res.viol });
}

console.log('Cases by mutation target:');
for (const k of Object.keys(mutClasses).sort()) console.log('  ' + k.padEnd(16) + String(mutClasses[k]).padStart(8));
console.log('');
console.log('Exceptions (Invariant A):        ' + exceptions);
console.log('False acceptances (Inv B):       ' + falseAccepts);
console.log('Typed-outcome violations (Inv C):' + typedViol);
console.log('Hard divergences (accept/reject):' + hardDiv);
console.log('Known divergences (reject-class): ' + knownDiv + '  (recorded, not failed)');
console.log('Non-determinism (Inv D):         ' + nondet);
console.log('Hangs/timeouts:                  0  (synchronous)');
console.log('');

const hardFail = exceptions + falseAccepts + typedViol + hardDiv + nondet;
if (hardFail || (negControl && falseAccepts === 0)) {
  if (failures.length) {
    try { const d = path.join(ROOT, 'test', 'fuzz-failures'); fs.mkdirSync(d, { recursive: true }); fs.writeFileSync(path.join(d, 'verifier-' + seed + '.json'), JSON.stringify(failures.slice(0, 200), null, 2)); } catch (_) {}
    console.log('FIRST FAILURES (reproduce: --seed ' + seed + ' --replay <iter>):');
    for (const f of failures.slice(0, 10)) console.log('  iter ' + f.iter + ' [' + (f.mutation || 'fatal') + '] ' + JSON.stringify(f.violations || f.fatal));
  }
  if (negControl && falseAccepts === 0) console.log('\nNEGATIVE CONTROL FAILED: planted false-VERIFIED not caught by Invariant B.');
  console.log('\nRESULT: FAIL');
  process.exit(1);
}
console.log('RESULT: PASS  (no uncaught exceptions, false acceptances, undocumented outcomes, accept/reject');
console.log('              divergences, or non-determinism in the ' + iters + ' shipped verifier.html cases tested at');
console.log('              this seed - testing evidence, not a security proof, and not all possible inputs)');
process.exit(0);
