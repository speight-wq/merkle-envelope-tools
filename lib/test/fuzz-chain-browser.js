'use strict';
/*
 * test/fuzz-chain-browser.js - deterministic, seed/replay fuzzing of the SHIPPED chain.html
 * verifyChain path.
 *
 * chain.html verifies a multi-hop transaction lineage: verifyChain(envelopes[]) validates each
 * envelope structurally (hex-checked txid/rawTx/blockHeader, proof array), checks ordering,
 * then per hop binds rawTx (txid == SHA256d(rawTx)), parses+PoW+floor-checks the header, folds
 * the LEGACY proof to the header root, and finally checks parent<-child linkage and value
 * continuity. result defaults to 'FAILED' and is set 'VALID' only after every phase passes;
 * verifyChain wraps the impl so any throw -> INDETERMINATE. It loads no header chain, so a
 * positive verdict is per-hop SPV (analogous to isolation), not checkpoint-anchored membership.
 *
 * The shipped IIFE body is run unchanged in a vm (real lib/*.js, DOM stub, fixed clock) to
 * expose verifyChain. Observer-only: no production file is modified.
 *
 * Invariants: A no uncaught exception escaping verifyChain; B no VERIFIED unless every hop
 * independently satisfies txid==SHA256d(rawTx), legacy-proof->header-root, and PoW; C a
 * documented typed outcome; D determinism; E no required stage silently skipped while the
 * verdict stays positive (subsumed by B: VALID requires the full binding).
 *
 * Run:
 *   node test/fuzz-chain-browser.js --seed 20260501 --iters 20000
 *   node test/fuzz-chain-browser.js --seed 20260501 --replay 4242
 *   node test/fuzz-chain-browser.js --seed 20260501 --iters 20000 --negative-control
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const IND = require(path.join(ROOT, 'headers-node-independent/verify.js'));
require(path.join(ROOT, 'lib/crypto.js'));
require(path.join(ROOT, 'lib/encoding.js'));
const ENV = JSON.parse(fs.readFileSync(path.join(ROOT, 'test/real-envelope.json'), 'utf8'));
const HEADER_TS = Buffer.from(ENV.blockHeader, 'hex').readUInt32LE(68);
const FIXED_CLOCK_MS = (HEADER_TS + 31536000) * 1000; // corpus header + 1yr, deterministic

// ---- run the shipped chain.html IIFE body so verifyChain is callable ---------------------
function buildContext(negControl) {
  const H = fs.readFileSync(path.join(ROOT, 'chain.html'), 'utf8');
  const scripts = [...H.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  const app = scripts.find(s => s.includes('verifyChain'));
  const start = app.indexOf('(function() {');
  let body = app.slice(start + '(function() {'.length, app.lastIndexOf('})();'));
  if (negControl) {
    // NEGATIVE CONTROL (test-only): force a failed Merkle check to be treated as a pass, so a
    // mutated proof that should FAIL is accepted. Invariant B must catch the resulting VALID.
    body = body.replace("if (computedRoot !== result.expectedMerkleRoot) {",
                        "if (false && computedRoot !== result.expectedMerkleRoot) {");
  }
  const c = {}; c.global = c; c.window = c; c.performance = { now: () => 0 };
  c.TextEncoder = TextEncoder; c.console = { log() {}, warn() {}, error() {} };
  c.Date = class extends Date { constructor(...a) { if (a.length) super(...a); else super(FIXED_CLOCK_MS); } static now() { return FIXED_CLOCK_MS; } };
  const els = {};
  const el = (id) => els[id] || (els[id] = { _v: '', _tc: '', _a: {}, addEventListener() {}, classList: { add() {}, remove() {} }, get value() { return this._v; }, set value(x) { this._v = x; }, set textContent(x) {}, set className(x) {}, set innerHTML(x) {}, setAttribute(k, v) { this._a[k] = v; }, querySelector() { return null; }, style: {} });
  c.document = { getElementById: el, addEventListener() {}, querySelector() { return null; }, querySelectorAll() { return []; }, createElement() { return el('x'); } };
  vm.createContext(c);
  for (const f of ['crypto.js', 'encoding.js', 'headers.js', 'bump.js', 'beef.js']) vm.runInContext(fs.readFileSync(path.join(ROOT, 'lib', f), 'utf8'), c);
  vm.runInContext(body, c);
  return c;
}
let CTX = null, CTX_NEG = null;
function shippedVerifyChain(envelopes, negControl) {
  const c = negControl ? (CTX_NEG || (CTX_NEG = buildContext(true))) : (CTX || (CTX = buildContext(false)));
  return c.verifyChain(envelopes);
}

// ---- deterministic PRNG + mutation helpers ------------------------------------------------
function mulberry32(a) { return function () { a |= 0; a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
function iterationRng(seed, i) { return mulberry32(((seed >>> 0) ^ Math.imul(i + 1, 2654435761)) >>> 0); }
const pick = (rng, a) => a[Math.floor(rng() * a.length)];
const randInt = (rng, n) => Math.floor(rng() * n);
const randByte = (rng) => Math.floor(rng() * 256);
const toHex = (b) => Buffer.from(b).toString('hex');
const fromHex = (h) => Buffer.from(h, 'hex');
const sha256d = (b) => crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest();

function mutateHexField(rng, hex) {
  const ops = ['flip', 'truncate', 'extend', 'zero-range', 'non-hex', 'non-hex-64', 'odd-length', 'empty', 'dup-region'];
  const op = pick(rng, ops);
  if (op === 'empty') return hex ? '' : 'a';
  if (op === 'odd-length') return hex.length ? hex.slice(0, hex.length - 1) : 'a';
  if (op === 'non-hex') { const at = randInt(rng, hex.length || 1); return hex.slice(0, at) + 'g' + hex.slice(at + 1); }
  if (op === 'non-hex-64') return 'g'.repeat(64);
  const b = fromHex(hex.length % 2 ? hex + '0' : hex);
  if (op === 'truncate') return toHex(b.subarray(0, randInt(rng, b.length + 1)));
  if (op === 'extend') return toHex(Buffer.concat([b, Buffer.from(Array.from({ length: 1 + randInt(rng, 8) }, () => randByte(rng)))]));
  if (op === 'flip') { if (b.length) b[randInt(rng, b.length)] ^= (1 << randInt(rng, 8)); return toHex(b); }
  if (op === 'zero-range') { if (b.length) { const a = randInt(rng, b.length); for (let i = a; i < Math.min(b.length, a + 1 + randInt(rng, 32)); i++) b[i] = 0; } return toHex(b); }
  if (b.length > 4) { const a = randInt(rng, b.length - 2); const len = 1 + randInt(rng, Math.min(16, b.length - a)); return toHex(Buffer.concat([b.subarray(0, a), b.subarray(a, a + len), b.subarray(a)])); }
  return hex;
}

// build the chain input (usually a single-hop [env]; sometimes array-level abuse)
function mutateChain(rng) {
  const env = JSON.parse(JSON.stringify(ENV)); delete env.bump; delete env.beef; delete env.atomicBeef; // chain uses legacy proof
  const strat = pick(rng, [
    'proof', 'proof', 'proof-pos', 'proof-depth', 'proof-nonarray',
    'header', 'header', 'txid', 'wrong-txid', 'rawTx', 'rawTx',
    'drop-header', 'drop-proof', 'drop-txid', 'drop-rawTx', 'empty-field',
    'type-confuse', 'empty-array', 'duplicate-hop', 'extra-field'
  ]);
  let mutation = strat, params = {};
  if (strat === 'empty-array') return { chain: [], mutation: 'empty-array', params };
  if (strat === 'duplicate-hop') return { chain: [JSON.parse(JSON.stringify(env)), JSON.parse(JSON.stringify(env))], mutation: 'duplicate-hop', params };
  if (strat === 'proof') { if (env.proof && env.proof.length) { const i = randInt(rng, env.proof.length); env.proof[i].hash = mutateHexField(rng, env.proof[i].hash); mutation = 'proof.hash'; params = { i }; } }
  else if (strat === 'proof-pos') { if (env.proof && env.proof.length) { const i = randInt(rng, env.proof.length); env.proof[i].pos = pick(rng, ['L', 'R', 'l', 'X', '', null]); mutation = 'proof.pos'; params = { i, pos: env.proof[i].pos }; } }
  else if (strat === 'proof-depth') { if (env.proof) { if (rng() < 0.5 && env.proof.length) env.proof = env.proof.slice(0, randInt(rng, env.proof.length)); else env.proof = (env.proof || []).concat([{ hash: 'ab'.repeat(32), pos: 'L' }]); mutation = 'proof.depth'; } }
  else if (strat === 'proof-nonarray') { env.proof = pick(rng, [null, {}, 'notarray', 123]); mutation = 'proof-nonarray'; }
  else if (strat === 'header') { env.blockHeader = mutateHexField(rng, env.blockHeader); mutation = 'header'; }
  else if (strat === 'txid') { env.txid = mutateHexField(rng, env.txid); mutation = 'txid'; }
  else if (strat === 'wrong-txid') { env.txid = 'ab'.repeat(32); mutation = 'wrong-txid'; }
  else if (strat === 'rawTx') { env.rawTx = mutateHexField(rng, env.rawTx); mutation = 'rawTx'; }
  else if (strat === 'drop-header') { delete env.blockHeader; mutation = 'drop-header'; }
  else if (strat === 'drop-proof') { delete env.proof; mutation = 'drop-proof'; }
  else if (strat === 'drop-txid') { delete env.txid; mutation = 'drop-txid'; }
  else if (strat === 'drop-rawTx') { delete env.rawTx; mutation = 'drop-rawTx'; }
  else if (strat === 'empty-field') { const f = pick(rng, ['blockHeader', 'txid', 'rawTx']); env[f] = ''; mutation = 'empty:' + f; }
  else if (strat === 'type-confuse') { const f = pick(rng, ['txid', 'blockHeader', 'rawTx', 'proof']); env[f] = pick(rng, [null, 123, true, {}, []]); mutation = 'type-confuse:' + f; }
  else if (strat === 'extra-field') { env['__x' + randInt(rng, 9)] = 'junk'; mutation = 'extra-field'; }
  return { chain: [env], mutation, params };
}

// ---- independent oracle for Invariant B (single hop; chain uses legacy proof + binds rawTx) --
const DOCUMENTED = new Set(['VERIFIED', 'VERIFIED-ISOLATION', 'FAILED', 'POLICY-REJECTED', 'MALFORMED', 'INDETERMINATE', 'NOT-ESTABLISHED']);
const ACCEPT = new Set(['VERIFIED', 'VERIFIED-ISOLATION']);
function hopBindingHolds(env) {
  try {
    if (typeof env.blockHeader !== 'string' || env.blockHeader.length !== 160) return false;
    if (typeof env.txid !== 'string' || env.txid.length !== 64) return false;
    if (typeof env.rawTx !== 'string') return false;
    // txid == SHA256d(rawTx)
    if (Buffer.from(sha256d(fromHex(env.rawTx))).reverse().toString('hex').toLowerCase() !== env.txid.toLowerCase()) return false;
    const hdr = IND.parseHeader(env.blockHeader);
    if (!IND.powOk(env.blockHeader, hdr.bits)) return false;
    const root = IND.rootFromLegacy(env.txid, Array.isArray(env.proof) ? env.proof : []);
    return root.toLowerCase() === hdr.merkleRootField.toLowerCase();
  } catch (_) { return false; }
}
// whole chain accepted only if every hop binds (single-hop covers the corpus)
function chainBindingHolds(chain) { return Array.isArray(chain) && chain.length > 0 && chain.every(hopBindingHolds); }

function runIteration(seed, i, opts) {
  opts = opts || {};
  const rng = iterationRng(seed, i);
  const { chain, mutation, params } = mutateChain(rng);
  const rec = { seed, iter: i, mutation, params, hops: Array.isArray(chain) ? chain.length : 'n/a' };
  const viol = [];
  let outcome = null, threw = null, resultStr = null;
  try {
    const r = shippedVerifyChain(chain, opts.negControl);
    outcome = r && r.outcome; resultStr = r && r.result;
  } catch (e) { threw = (e && e.message) || String(e); viol.push('A: verifyChain threw uncaught (' + threw + ')'); }
  rec.shipped = threw ? ('throw:' + threw) : (outcome + '/' + resultStr);

  if (outcome != null) {
    if (!DOCUMENTED.has(outcome)) viol.push('C: undocumented outcome ' + outcome);
    if (ACCEPT.has(outcome) && !chainBindingHolds(chain)) viol.push('B: shipped ' + outcome + ' but chain binding does not hold');
  }

  // differential (single-hop) vs the independent verifier on the same legacy-proof envelope.
  // chain->VERIFIED while independent(no chain)->VERIFIED-ISOLATION: both ACCEPT (known label diff).
  if (Array.isArray(chain) && chain.length === 1) {
    let indOut = null;
    try { indOut = IND.verify(chain[0], { bindRawTx: true }).outcome; } catch (_) { indOut = 'THREW'; }
    rec.independent = indOut;
    if (outcome != null && indOut && indOut !== 'THREW' && outcome !== indOut) {
      const shipAccept = ACCEPT.has(outcome), indAccept = ACCEPT.has(indOut);
      if (shipAccept && !indAccept) {
        // chain ACCEPTS, independent REJECTS -> a concern only if the binding does not hold
        // (Invariant B already covers that). If it holds, independent is merely stricter.
        if (!chainBindingHolds(chain)) viol.push('DIFF-HARD: shipped ' + outcome + ' accepted while independent rejects and binding does not hold (' + indOut + ')');
        else rec.knownDivergence = 'chain accepts on a holding binding; independent stricter (' + outcome + '/' + indOut + ')';
      } else if (!shipAccept && indAccept) {
        // chain REJECTS what the (leniency-carrying) independent verifier accepts -> chain is
        // stricter and fail-closed (e.g. chain requires rawTx; independent skips absent rawTx).
        rec.knownDivergence = 'chain stricter: rejects (' + outcome + ') what independent accepts (' + indOut + ')';
      } else {
        rec.knownDivergence = 'both ' + (shipAccept ? 'accept' : 'reject') + ', class differs (' + outcome + '/' + indOut + ')';
      }
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
  const a = runIteration(seed, replay, { negControl });
  const b = runIteration(seed, replay, { negControl });
  console.log('REPLAY seed=' + seed + ' iteration=' + replay);
  console.log(JSON.stringify(a.rec, null, 2));
  console.log('violations:', a.viol.length ? a.viol : 'none');
  console.log('deterministic:', JSON.stringify(a.rec) === JSON.stringify(b.rec));
  process.exit(a.viol.length ? 1 : 0);
}

console.log('Merkle Envelope Tools - shipped HTML verify() fuzz (chain.html)\n');
console.log('Seed:       ' + seed);
console.log('Iterations: ' + iters);
console.log('Fixed clock:' + new Date(FIXED_CLOCK_MS).toISOString() + ' (corpus header + 1yr; test-only)');
if (negControl) console.log('MODE:       NEGATIVE CONTROL (planted Merkle-check bypass in a temp chain.html copy)');
console.log('');

const mutClasses = {};
let exceptions = 0, falseAccepts = 0, typedViol = 0, hardDiv = 0, knownDiv = 0, nondet = 0;
const failures = [];
for (let i = 0; i < iters; i++) {
  let res;
  try { res = runIteration(seed, i, { negControl }); }
  catch (e) { exceptions++; failures.push({ seed, iter: i, fatal: String(e && e.stack || e) }); continue; }
  const cls = res.rec.mutation.split(':')[0];
  mutClasses[cls] = (mutClasses[cls] || 0) + 1;
  const res2 = runIteration(seed, i, { negControl });
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
console.log('Known divergences (label/class):  ' + knownDiv + '  (recorded, not failed)');
console.log('Non-determinism (Inv D):         ' + nondet);
console.log('Hangs/timeouts:                  0  (synchronous)');
console.log('');

const hardFail = exceptions + falseAccepts + typedViol + hardDiv + nondet;
if (hardFail || (negControl && falseAccepts === 0)) {
  if (failures.length) {
    try { const d = path.join(ROOT, 'test', 'fuzz-failures'); fs.mkdirSync(d, { recursive: true }); fs.writeFileSync(path.join(d, 'chain-' + seed + '.json'), JSON.stringify(failures.slice(0, 200), null, 2)); } catch (_) {}
    console.log('FIRST FAILURES (reproduce: --seed ' + seed + ' --replay <iter>):');
    for (const f of failures.slice(0, 10)) console.log('  iter ' + f.iter + ' [' + (f.mutation || 'fatal') + '] ' + JSON.stringify(f.violations || f.fatal));
  }
  if (negControl && falseAccepts === 0) console.log('\nNEGATIVE CONTROL FAILED: planted Merkle bypass not caught by Invariant B.');
  console.log('\nRESULT: FAIL');
  process.exit(1);
}
console.log('RESULT: PASS  (no uncaught exceptions, false acceptances, undocumented outcomes, accept/reject');
console.log('              divergences, or non-determinism in the ' + iters + ' shipped chain.html cases tested at');
console.log('              this seed - testing evidence, not a security proof, and not all possible inputs)');
process.exit(0);
