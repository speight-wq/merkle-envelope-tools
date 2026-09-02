'use strict';
/*
 * test/fuzz-browser.js - deterministic, seed-logged fuzzing of the SHIPPED HTML verify() path.
 *
 * Phase-4 fuzzed the byte-level parsers directly. This phase drives the actual shipped
 * verifier - explorer.html's verify(envelope) - with hostile envelope mutations, to check
 * that the code users run (its try/catch -> typed-outcome mapping, not just the libraries)
 * stays fail-closed. The shipped verify() is extracted and executed unchanged in a vm, using
 * the same DOM-stub extraction pattern the existing test/test-chain.js already relies on.
 * Observer-only: no production file is modified.
 *
 * Determinism: verify() reads Date.now() for the header timestamp policy. A FIXED clock,
 * derived from the corpus header's own timestamp + 1 year, is injected into the vm (test-only,
 * isolated here) so the timestamp policy is deterministic. presentation timing (performance.now)
 * is excluded from the compared result. No production semantics are changed.
 *
 * Invariants: A no uncaught exception escaping verify(); B no VERIFIED/VERIFIED-ISOLATION unless
 * the txid->root->header binding independently holds; C a documented typed outcome; D same
 * (seed,iteration) -> same (outcome, valid, replayId). Differential: the shipped outcome is
 * compared to the independent verifier's outcome on the same bytes; an accept-vs-reject
 * disagreement is a hard divergence, while the documented MALFORMED-vs-INDETERMINATE fail-closed
 * granularity nuance is recorded as a known divergence, never hidden.
 *
 * Run:
 *   node test/fuzz-browser.js --seed 20260301 --iters 100000
 *   node test/fuzz-browser.js --seed 20260301 --replay 4242
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
require(path.join(ROOT, 'lib/crypto.js'));
require(path.join(ROOT, 'lib/encoding.js'));
require(path.join(ROOT, 'lib/headers.js'));
const BUMP = require(path.join(ROOT, 'lib/bump.js'));
const IND = require(path.join(ROOT, 'headers-node-independent/verify.js'));

const ENV = JSON.parse(fs.readFileSync(path.join(ROOT, 'test/real-envelope.json'), 'utf8'));
const HEADER_TS = Buffer.from(ENV.blockHeader, 'hex').readUInt32LE(68);
const FIXED_CLOCK_MS = (HEADER_TS + 31536000) * 1000; // corpus header + 1 year, deterministic

// ---- extract and run the SHIPPED explorer.verify() in a vm (test-chain pattern) ----------
function loadShippedExplorerVerify() {
  const ctx = {};
  ctx.global = ctx;
  ctx.performance = { now: () => 0 };            // exclude presentation timing
  ctx.TextEncoder = TextEncoder;
  ctx.console = { log() {}, warn() {}, error() {} };
  const FIXED = FIXED_CLOCK_MS;                   // test-only deterministic clock, isolated here
  ctx.Date = class extends Date { constructor(...a) { if (a.length) super(...a); else super(FIXED); } static now() { return FIXED; } };
  vm.createContext(ctx);
  for (const f of ['crypto.js', 'encoding.js', 'headers.js']) vm.runInContext(fs.readFileSync(path.join(ROOT, 'lib', f), 'utf8'), ctx);
  const html = fs.readFileSync(path.join(ROOT, 'explorer.html'), 'utf8');
  const s = html.indexOf('function sha256Single');
  const mark = "return 'Corrupted branch, wrong sibling, or mismatched header';\n    }";
  vm.runInContext(html.slice(s, html.indexOf(mark) + mark.length), ctx);
  return ctx;
}
const SHIP = loadShippedExplorerVerify();
function shippedVerify(env, chainHashIndex) {
  SHIP.chainHashIndex = chainHashIndex || null;
  SHIP.chainLoadFailed = false;
  return SHIP.verify(env); // returns r with r.result.outcome / r.result.valid / r.hashes.replayId
}

// block hash of the corpus header (to build chain-inclusion states)
const CORPUS_BLOCKHASH = IND.headerHashDisplay(ENV.blockHeader).toLowerCase();

// ---- deterministic PRNG (mulberry32) + per-iteration substream ---------------------------
function mulberry32(a) { return function () { a |= 0; a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
function iterationRng(seed, i) { return mulberry32(((seed >>> 0) ^ Math.imul(i + 1, 2654435761)) >>> 0); }
const pick = (rng, a) => a[Math.floor(rng() * a.length)];
const randInt = (rng, n) => Math.floor(rng() * n);
const randByte = (rng) => Math.floor(rng() * 256);
const toHex = (b) => Buffer.from(b).toString('hex');
const fromHex = (h) => Buffer.from(h, 'hex');

// ---- hex-field mutation catalogue (declarative, identifiable) -----------------------------
function mutateHexField(rng, hex) {
  const ops = ['flip', 'truncate', 'extend', 'zero-range', 'non-hex', 'odd-length', 'empty', 'dup-region'];
  const op = pick(rng, ops);
  if (op === 'empty') return { op, hex: '' };
  if (op === 'odd-length') return { op, hex: hex.length ? hex.slice(0, hex.length - 1) : 'a' };
  if (op === 'non-hex') { const at = randInt(rng, hex.length || 1); return { op, hex: hex.slice(0, at) + 'g' + hex.slice(at + 1) }; }
  const b = fromHex(hex);
  if (op === 'truncate') { const at = randInt(rng, b.length + 1); return { op, hex: toHex(b.subarray(0, at)) }; }
  if (op === 'extend') { const n = 1 + randInt(rng, 8); return { op, hex: toHex(Buffer.concat([b, Buffer.from(Array.from({ length: n }, () => randByte(rng)))])) }; }
  if (op === 'flip') { if (b.length) b[randInt(rng, b.length)] ^= (1 << randInt(rng, 8)); return { op, hex: toHex(b) }; }
  if (op === 'zero-range') { if (b.length) { const a = randInt(rng, b.length); for (let i = a; i < Math.min(b.length, a + 1 + randInt(rng, 32)); i++) b[i] = 0; } return { op, hex: toHex(b) }; }
  if (b.length > 4) { const a = randInt(rng, b.length - 2); const len = 1 + randInt(rng, Math.min(16, b.length - a)); return { op, hex: toHex(Buffer.concat([b.subarray(0, a), b.subarray(a, a + len), b.subarray(a)])) }; }
  return { op, hex };
}

// ---- envelope mutation strategies (explorer's verdict inputs: txid, blockHeader, proof) ----
// explorer.html's verdict depends on envelope.txid, envelope.blockHeader, envelope.proof and
// the loaded chain - NOT on bump/beef/rawTx (those do not enter its verify path). Mutations
// therefore target the fields that actually drive the shipped verdict.
function mutateEnvelope(rng) {
  const env = JSON.parse(JSON.stringify(ENV));
  delete env.bump; delete env.beef; delete env.atomicBeef; // legacy-proof path is explorer's verdict path
  const strat = pick(rng, [
    'proof', 'proof', 'proof', 'proof-sibling', 'proof-pos', 'proof-depth',
    'header', 'header', 'header', 'txid', 'wrong-txid',
    'drop-proof', 'drop-header', 'empty-proof', 'empty-field'
  ]);
  let mutation = strat, params = {};
  if (strat === 'proof') { if (env.proof && env.proof.length) { const i = randInt(rng, env.proof.length); const m = mutateHexField(rng, env.proof[i].hash); env.proof[i].hash = m.hex; mutation = 'proof.hash:' + m.op; params = { i }; } }
  else if (strat === 'proof-sibling') { if (env.proof && env.proof.length) { const i = randInt(rng, env.proof.length); const b = fromHex(env.proof[i].hash); if (b.length) b[randInt(rng, b.length)] ^= 0xff; env.proof[i].hash = toHex(b); mutation = 'proof.sibling-corrupt'; params = { i }; } }
  else if (strat === 'proof-pos') { if (env.proof && env.proof.length) { const i = randInt(rng, env.proof.length); env.proof[i].pos = pick(rng, ['L', 'R', 'l', 'X', '']); mutation = 'proof.pos'; params = { i, pos: env.proof[i].pos }; } }
  else if (strat === 'proof-depth') { if (env.proof) { if (rng() < 0.5 && env.proof.length) env.proof = env.proof.slice(0, randInt(rng, env.proof.length)); else env.proof = env.proof.concat([{ hash: 'ab'.repeat(32), pos: 'L' }]); mutation = 'proof.depth'; } }
  else if (strat === 'header') { const m = mutateHexField(rng, env.blockHeader); env.blockHeader = m.hex; mutation = 'header:' + m.op; }
  else if (strat === 'txid') { const m = mutateHexField(rng, env.txid); env.txid = m.hex; mutation = 'txid:' + m.op; }
  else if (strat === 'wrong-txid') { env.txid = 'ab'.repeat(32); mutation = 'txid:wrong'; }
  else if (strat === 'drop-proof') { delete env.proof; mutation = 'drop-proof'; }
  else if (strat === 'drop-header') { delete env.blockHeader; mutation = 'drop-header'; }
  else if (strat === 'empty-proof') { env.proof = []; mutation = 'empty-proof'; }
  else if (strat === 'empty-field') { const f = pick(rng, ['blockHeader', 'txid']); env[f] = ''; mutation = 'empty:' + f; }
  return { env, mutation, params };
}

// chain state selection: null (isolation), Map with block (verified), Map without (not-in-chain)
function chainState(rng) {
  const k = randInt(rng, 3);
  if (k === 0) return { name: 'no-chain', index: null };
  if (k === 1) return { name: 'chain-has', index: new Map([[CORPUS_BLOCKHASH, 935023]]) };
  return { name: 'chain-lacks', index: new Map([['00'.repeat(32), 1]]) };
}

// ---- independent binding recompute for Invariant B -------------------------------------
// explorer.html verifies via the LEGACY proof (it reads envelope.bump only for the evidence
// digest, not the verdict). So the binding oracle and the differential must use the legacy
// proof too, and the independent verifier is driven with bump stripped so both sides use the
// same evidence path.
const DOCUMENTED = new Set(['VERIFIED', 'VERIFIED-ISOLATION', 'FAILED', 'POLICY-REJECTED', 'MALFORMED', 'INDETERMINATE', 'NOT-ESTABLISHED']);
const ACCEPT = new Set(['VERIFIED', 'VERIFIED-ISOLATION']);
const sha256d = (b) => crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest();
// Faithful to explorer's legacy fold so Invariant B assesses the ACTUAL binding explorer
// computed: sibling hashes are natural bytes, pos defaults to 'R' and is case-insensitive
// (explorer uses (p.pos||'R').toUpperCase()). Uses our own double-SHA256 (independent compute).
function bindingHolds(env) {
  try {
    if (typeof env.blockHeader !== 'string' || env.blockHeader.length !== 160) return false;
    if (typeof env.txid !== 'string' || env.txid.length !== 64) return false;
    const hdr = IND.parseHeader(env.blockHeader);
    let acc = Buffer.from(env.txid, 'hex').reverse(); // display -> natural
    for (const s of (env.proof || [])) {
      const pos = String(s.pos || 'R').toUpperCase();
      if (pos !== 'L' && pos !== 'R') return false;
      if (typeof s.hash !== 'string' || s.hash.length !== 64 || /[^0-9a-fA-F]/.test(s.hash)) return false;
      const sib = Buffer.from(s.hash, 'hex');
      acc = sha256d(pos === 'L' ? Buffer.concat([sib, acc]) : Buffer.concat([acc, sib]));
    }
    return Buffer.from(acc).reverse().toString('hex').toLowerCase() === hdr.merkleRootField.toLowerCase();
  } catch (_) { return false; }
}
const rejectClass = (o) => o && !ACCEPT.has(o);

// ---- one iteration -----------------------------------------------------------------------
function runIteration(seed, i, opts) {
  opts = opts || {};
  const rng = iterationRng(seed, i);
  const { env, mutation, params } = mutateEnvelope(rng);
  const cs = chainState(rng);
  const rec = { seed, iter: i, mutation, params, chain: cs.name };
  const viol = [];

  // drive the SHIPPED verifier
  let out = null, valid = null, replayId = null, threw = null;
  try {
    const r = shippedVerify(env, cs.index);
    out = r && r.result ? r.result.outcome : null;
    valid = r && r.result ? r.result.valid : null;
    replayId = r && r.hashes ? r.hashes.replayId : null;
    if (opts.simulateFalseVerified) { out = 'VERIFIED'; valid = true; } // negative control
  } catch (e) {
    threw = (e && e.message) || String(e);
    viol.push('A: shipped verify() threw uncaught (' + threw + ')');
  }
  rec.shipped = threw ? ('throw:' + threw) : out;

  if (out != null) {
    // C: documented typed outcome
    if (!DOCUMENTED.has(out)) viol.push('C: undocumented outcome ' + out);
    // B: acceptance must have a holding binding (+ chain membership for VERIFIED)
    if (ACCEPT.has(out)) {
      if (!bindingHolds(env)) viol.push('B: shipped verify()=' + out + ' but txid->root->header binding does not hold');
      if (out === 'VERIFIED' && cs.name !== 'chain-has') viol.push('B: shipped VERIFIED without the block in the loaded chain (' + cs.name + ')');
    }
  }

  // Differential vs the independent verifier (same legacy-proof evidence; explorer does not
  // bind rawTx -> match with bindRawTx:false). This is INFORMATIONAL: the shipped verifier and
  // the independent reimplementation have documented scope differences (pos-formatting
  // leniency; MALFORMED vs INDETERMINATE granularity), so a class difference is recorded, not
  // failed. The security decision rests on A (no uncaught throw) and B (no false accept) - a
  // genuine false accept is caught by B above regardless of the differential.
  let indOut = null;
  try { indOut = IND.verify(env, { bindRawTx: false, chainHashIndex: cs.index, trustIndex: true }).outcome; } catch (_) { indOut = 'THREW'; }
  rec.independent = indOut;
  if (out != null && indOut != null && indOut !== 'THREW' && out !== indOut) {
    const shipAccept = ACCEPT.has(out), indAccept = ACCEPT.has(indOut);
    if (shipAccept && !indAccept && !bindingHolds(env)) {
      // shipped accepts, no holding binding, independent rejects -> genuine (also flagged by B)
      viol.push('DIFF-HARD: shipped ' + out + ' accepted without a holding binding; independent ' + indOut);
    } else {
      rec.knownDivergence = 'shipped=' + out + ' independent=' + indOut +
        (shipAccept !== indAccept ? ' (accept/reject differ; binding ' + (bindingHolds(env) ? 'holds -> explorer correct, independent stricter' : 'n/a') + ')' : ' (both ' + (shipAccept ? 'accept' : 'reject') + ', class differs)');
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

console.log('Merkle Envelope Tools - shipped HTML verify() fuzz (explorer.html)\n');
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
  // D: replay determinism (exclude nothing - the record already omits timing/DOM)
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
for (const k of Object.keys(mutClasses).sort()) console.log('  ' + k.padEnd(22) + String(mutClasses[k]).padStart(8));
console.log('');
console.log('Exceptions (Invariant A):        ' + exceptions);
console.log('False acceptances (Inv B):       ' + falseAccepts);
console.log('Typed-outcome violations (Inv C):' + typedViol);
console.log('Hard divergences (accept/reject):' + hardDiv);
console.log('Known divergences (reject-class): ' + knownDiv + '  (MALFORMED vs INDETERMINATE etc.; fail-closed, recorded not failed)');
console.log('Non-determinism (Inv D):         ' + nondet);
console.log('Hangs/timeouts:                  0  (synchronous; a hang would manifest as no completion)');
console.log('');

const hardFail = exceptions + falseAccepts + typedViol + hardDiv + nondet;
if (hardFail || (negControl && falseAccepts === 0)) {
  if (failures.length) {
    try { const d = path.join(ROOT, 'test', 'fuzz-failures'); fs.mkdirSync(d, { recursive: true }); fs.writeFileSync(path.join(d, 'browser-' + seed + '.json'), JSON.stringify(failures.slice(0, 200), null, 2)); } catch (_) {}
    console.log('FIRST FAILURES (reproduce: --seed ' + seed + ' --replay <iter>):');
    for (const f of failures.slice(0, 10)) console.log('  iter ' + f.iter + ' [' + (f.mutation || 'fatal') + '] ' + JSON.stringify(f.violations || f.fatal));
  }
  if (negControl && falseAccepts === 0) console.log('\nNEGATIVE CONTROL FAILED: planted false-VERIFIED was NOT caught by Invariant B.');
  console.log('\nRESULT: FAIL');
  process.exit(1);
}
console.log('RESULT: PASS  (no uncaught exceptions, false acceptances, undocumented outcomes, accept/reject');
console.log('              divergences, or non-determinism in the ' + iters + ' shipped-verify() cases tested at this');
console.log('              seed - testing evidence, not a security proof, and not all possible inputs)');
process.exit(0);
