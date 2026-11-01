'use strict';
/*
 * test/fuzz.js - deterministic, seed-logged parser fuzzing for Merkle Envelope Tools.
 *
 * Purpose (distinct from test/validate.js, which validates VALID inputs against an independent
 * oracle): attack the byte-level parsers with structured HOSTILE mutations of known-valid
 * corpus items, and establish that malformed/adversarial input fails safely, deterministically,
 * and with a correct typed outcome. The fuzzer is an OBSERVER - it never modifies production
 * code. If it finds a defect it records a reproducer and stops; the fix is a separate pass.
 *
 * Targets: BUMP (BRC-74), block header + PoW (targetFromNBits/verifyPoW), headers.bin loader,
 * and BEEF (lighter - the independent verifier does not implement BEEF, so BEEF is checked for
 * safe typed rejection only, not differentially).
 *
 * Invariants asserted per case:
 *   A  no UNEXPECTED exception - a parser may throw an Error to reject (expected); it must not
 *      throw a non-Error, and the full independent verify() must always return a typed outcome.
 *   B  no FALSE acceptance - if a mutated envelope verifies (VERIFIED / VERIFIED-ISOLATION),
 *      the txid->root->header binding must independently still hold. Mutations are NOT assumed
 *      to always invalidate (some are semantics-preserving).
 *   C  typed outcome - the independent verify() result is one of the frozen OUTCOME values.
 *   D  determinism - the same (seed, iteration) yields the same mutated bytes and same result.
 *
 * Differential: the same mutated bytes go to the production lib parser AND the independent
 * reimplementation; outcome CLASSES must agree (both reject, or both accept with equal root),
 * accounting for documented scope differences. Disagreements are recorded, never hidden.
 *
 * Run:
 *   node test/fuzz.js --seed 123456789 --iters 100000
 *   node test/fuzz.js --seed 123456789 --replay 4242      (re-run one iteration, full record)
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
// production libs (attach to global) - load order per the HTML pages
require(path.join(ROOT, 'lib/crypto.js'));
require(path.join(ROOT, 'lib/encoding.js'));
require(path.join(ROOT, 'lib/headers.js'));
const BUMP = require(path.join(ROOT, 'lib/bump.js'));
const BEEF = require(path.join(ROOT, 'lib/beef.js'));
const IND = require(path.join(ROOT, 'headers-node-independent/verify.js'));
const G = global;

// ---- deterministic PRNG (mulberry32); per-iteration independent, replayable ----------
function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function iterationRng(seed, i) { return mulberry32(((seed >>> 0) ^ Math.imul(i + 1, 2654435761)) >>> 0); }
const pick = (rng, arr) => arr[Math.floor(rng() * arr.length)];
const randByte = (rng) => Math.floor(rng() * 256);
const randInt = (rng, n) => Math.floor(rng() * n);

// ---- hex helpers (local; not the modules under test) ---------------------------------
const toHex = (b) => Buffer.from(b).toString('hex');
const fromHex = (h) => Buffer.from(h, 'hex');
const sha256d = (b) => crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest();

// ---- corpus (valid seeds; reuse existing fixtures) -----------------------------------
const ENV = JSON.parse(fs.readFileSync(path.join(ROOT, 'test/real-envelope.json'), 'utf8'));
const HEADERS_BIN = fs.readFileSync(path.join(ROOT, 'test/headers-940000-to-940000.bin'));
// ---- deterministic valid BEEF corpus: plain / multi(ancestor) / atomic(subject+ancestor) --
function buildBeefCorpus() {
  const out = [];
  const S = (x) => String(x).toLowerCase();
  const le = (n, b) => { const x = Buffer.alloc(b); let v = n; for (let i = 0; i < b; i++) { x[i] = v & 0xff; v = Math.floor(v / 256); } return x; };
  const vi = (n) => n < 0xfd ? Buffer.from([n]) : Buffer.concat([Buffer.from([0xfd]), le(n, 2)]);
  // a deterministic child tx spending (prevTxid:prevVout); fixed bytes, no randomness
  const childTx = (prevTxid, prevVout, tag) => {
    const p = [le(1, 4), vi(1)];
    p.push(Buffer.from(prevTxid, 'hex').reverse(), le(prevVout, 4), vi(3), Buffer.from([tag, tag, tag]), le(0xffffffff, 4));
    p.push(vi(1), le(1000, 8), vi(2), Buffer.from([0x51, 0x51]));
    p.push(le(0, 4));
    return Buffer.concat(p).toString('hex');
  };
  try {
    const bump = BUMP.fromHex(ENV.bump);
    const txid0 = BEEF.txidOf(ENV.rawTx);
    const raw1 = childTx(txid0, 0, 0xab), txid1 = BEEF.txidOf(raw1);
    const plain = S(BEEF.build({ bumps: [bump], transactions: [{ rawHex: ENV.rawTx, bumpIndex: 0 }] }));
    const multi = S(BEEF.build({ bumps: [bump], transactions: [{ rawHex: ENV.rawTx, bumpIndex: 0 }, { rawHex: raw1, bumpIndex: null }] }));
    const atomic = S(BEEF.wrapAtomic(multi, txid1));
    out.push({ id: 'plain', hex: plain, atomic: false, subject: null });
    out.push({ id: 'multi-ancestor', hex: multi, atomic: false, subject: null });
    out.push({ id: 'atomic-subject-ancestor', hex: atomic, atomic: true, subject: txid1 });
  } catch (_) { /* if the build shape differs, BEEF target simply has less corpus */ }
  return out;
}

const CORPUS = {
  bump: [{ id: 'brc74-vector', hex: BUMP.VECTOR.hex, txid: BUMP.VECTOR.txids[0], root: BUMP.VECTOR.root },
         { id: 'real-envelope-bump', hex: ENV.bump, txid: ENV.txid }],
  header: [{ id: 'real-header', hex: ENV.blockHeader }],
  headersbin: [{ id: 'headers-940000', bytes: HEADERS_BIN }],
  beef: buildBeefCorpus()
};

// ---- mutation primitives on a byte buffer --------------------------------------------
function mutateBytes(rng, buf) {
  const ops = ['flip', 'truncate', 'extend', 'zero-range', 'set-ff-range', 'empty', 'dup-region'];
  const op = pick(rng, ops);
  let out, detail;
  if (op === 'empty') { out = Buffer.alloc(0); detail = {}; }
  else if (op === 'truncate') { const at = randInt(rng, buf.length + 1); out = buf.subarray(0, at); detail = { at }; }
  else if (op === 'extend') { const n = 1 + randInt(rng, 8); const tail = Buffer.from(Array.from({ length: n }, () => randByte(rng))); out = Buffer.concat([buf, tail]); detail = { n }; }
  else if (op === 'flip') { out = Buffer.from(buf); if (out.length) { const at = randInt(rng, out.length); out[at] ^= (1 << randInt(rng, 8)); detail = { at }; } else detail = {}; }
  else if (op === 'zero-range' || op === 'set-ff-range') { out = Buffer.from(buf); const v = op === 'zero-range' ? 0 : 0xff; if (out.length) { const a = randInt(rng, out.length); const b = Math.min(out.length, a + 1 + randInt(rng, 32)); for (let i = a; i < b; i++) out[i] = v; detail = { a, b }; } else detail = {}; }
  else { out = Buffer.from(buf); if (out.length > 4) { const a = randInt(rng, out.length - 2); const len = 1 + randInt(rng, Math.min(16, out.length - a)); out = Buffer.concat([out.subarray(0, a), out.subarray(a, a + len), out.subarray(a)]); detail = { a, len }; } else detail = {}; }
  return { op, detail, bytes: out };
}
function mutateHexString(rng, hex) {
  // hex-level mutations that don't just reduce to byte mutations
  const ops = ['odd-length', 'non-hex-char', 'as-bytes'];
  const op = pick(rng, ops);
  if (op === 'odd-length') return { op, detail: {}, hex: hex.slice(0, Math.max(1, hex.length - 1)) };
  if (op === 'non-hex-char') { const at = randInt(rng, hex.length || 1); const bad = 'ghijklmnopqrstuvwxyz'[randInt(rng, 20)]; return { op, detail: { at }, hex: hex.slice(0, at) + bad + hex.slice(at + 1) }; }
  const m = mutateBytes(rng, fromHex(hex)); return { op: 'bytes:' + m.op, detail: m.detail, hex: toHex(m.bytes) };
}

// ---- outcome-class helpers -----------------------------------------------------------
const ACCEPT = new Set([IND.OUT.VERIFIED, IND.OUT.VERIFIED_ISOLATION]);
function classifyThrow(e) {
  if (e instanceof IND.Malformed) return 'MALFORMED';
  if (e instanceof IND.Contradicted) return 'FAILED';
  if (e instanceof IND.PolicyReject) return 'POLICY-REJECTED';
  if (e instanceof IND.EvalFailure) return 'EVAL';
  if (e instanceof Error) return 'error:' + (e.message || '').slice(0, 40);
  return 'NON-ERROR-THROW'; // Invariant A violation candidate
}
// independent recompute of the txid->root binding for Invariant B
function bindingHolds(env) {
  try {
    const hdr = IND.parseHeader(env.blockHeader);
    let root;
    if (env.bump != null) root = IND.rootFromBump(IND.parseBump(env.bump), env.txid);
    else root = IND.rootFromLegacy(env.txid, env.proof || []);
    return root.toLowerCase() === hdr.merkleRootField.toLowerCase();
  } catch (_) { return false; }
}

// ---- per-target case runners: return a record + list of invariant violations ---------
function runBump(rng, seed, iter) {
  const c = pick(rng, CORPUS.bump);
  const useHexMut = rng() < 0.3;
  const m = useHexMut ? mutateHexString(rng, c.hex) : (function () { const mm = mutateBytes(rng, fromHex(c.hex)); return { op: 'bytes:' + mm.op, detail: mm.detail, hex: toHex(mm.bytes) }; })();
  const rec = { target: 'BUMP', corpusId: c.id, mutation: m.op, params: m.detail, seed, iter, mutatedHex: m.hex };
  const viol = [];
  // production lib
  let libRoot = null, libThrow = null;
  try { libRoot = BUMP.merkleRoot(BUMP.fromHex(m.hex), c.txid); }
  catch (e) { libThrow = classifyThrow(e); if (libThrow === 'NON-ERROR-THROW') viol.push('A: lib BUMP non-Error throw'); }
  // independent
  let indRoot = null, indThrow = null;
  try { indRoot = IND.rootFromBump(IND.parseBump(m.hex), c.txid); }
  catch (e) { indThrow = classifyThrow(e); if (indThrow === 'NON-ERROR-THROW') viol.push('A: ind BUMP non-Error throw'); }
  // differential: both throw, or both return equal root
  const bothThrew = libThrow && indThrow;
  const bothRoot = libRoot != null && indRoot != null;
  if (!bothThrew) {
    if (bothRoot && libRoot.toLowerCase() !== indRoot.toLowerCase()) viol.push('DIFF: BUMP roots differ lib=' + libRoot + ' ind=' + indRoot);
    else if ((libRoot != null) !== (indRoot != null)) viol.push('DIFF: BUMP one parsed one threw (lib=' + (libRoot || libThrow) + ' ind=' + (indRoot || indThrow) + ')');
  }
  // B: a returned root that equals the ORIGINAL valid root while the input was mutated and the
  // txid is the original -> only a problem if it claims the original root without proving it.
  if (c.root && libRoot && libRoot.toLowerCase() === c.root.toLowerCase()) {
    // recompute independently: does the mutated bump actually contain a path for txid to c.root?
    if (indRoot == null || indRoot.toLowerCase() !== c.root.toLowerCase())
      viol.push('B: lib BUMP returned original root from a mutation the independent impl does not confirm');
  }
  rec.lib = libRoot || ('throw:' + libThrow); rec.ind = indRoot || ('throw:' + indThrow);
  return { rec, viol };
}

function runHeader(rng, seed, iter) {
  const c = pick(rng, CORPUS.header);
  const b = Buffer.from(fromHex(c.hex));
  // targeted nBits exponents + generic field mutation
  const nbitsExps = [0x00, 0x01, 0x02, 0x03, 0x04, 0x21, 0xff];
  const strat = pick(rng, ['nbits-exp', 'nbits-signbit', 'nbits-mant0', 'nbits-mantmax', 'field-flip', 'truncate']);
  let mutation = strat, params = {};
  if (b.length === 80 && strat.startsWith('nbits')) {
    let mant = (b[72]) | (b[73] << 8) | (b[74] << 16); // LE mantissa (low 3 bytes)
    let exp = b[75];
    if (strat === 'nbits-exp') { exp = pick(rng, nbitsExps); params = { exp }; }
    else if (strat === 'nbits-signbit') { mant |= 0x800000; params = { signbit: true }; }
    else if (strat === 'nbits-mant0') { mant = 0; params = { mant: 0 }; }
    else if (strat === 'nbits-mantmax') { mant = 0x7fffff; params = { mant: 'max' }; }
    b[72] = mant & 0xff; b[73] = (mant >> 8) & 0xff; b[74] = (mant >> 16) & 0xff; b[75] = exp & 0xff;
  } else if (strat === 'field-flip' && b.length === 80) { const at = randInt(rng, 80); b[at] ^= (1 << randInt(rng, 8)); params = { at }; }
  else { const at = randInt(rng, b.length + 1); return finishHeader(c, b.subarray(0, at), 'truncate', { at }, seed, iter); }
  return finishHeader(c, b, mutation, params, seed, iter);
}
function finishHeader(c, b, mutation, params, seed, iter) {
  const hex = toHex(b);
  const rec = { target: 'Header', corpusId: c.id, mutation, params, seed, iter, mutatedHex: hex };
  const viol = [];
  // targetFromNBits: pure + deterministic. Compare lib vs independent.
  let libTgt = null, libThrow = null, indTgt = null, indThrow = null;
  if (b.length === 80) {
    const nBits = b.readUInt32LE(72);
    try { libTgt = G.targetFromNBits(nBits); } catch (e) { libThrow = classifyThrow(e); }
    try { indTgt = IND.targetFromBits(nBits); } catch (e) { indThrow = classifyThrow(e); }
    if (libThrow === 'NON-ERROR-THROW') viol.push('A: lib targetFromNBits non-Error throw');
    if (!(libThrow && indThrow) && libTgt != null && indTgt != null && libTgt.toString() !== indTgt.toString())
      viol.push('DIFF: targetFromNBits lib=' + libTgt + ' ind=' + indTgt + ' (nBits=' + nBits.toString(16) + ')');
    if ((libTgt != null) !== (indTgt != null)) viol.push('DIFF: target one threw one returned (nBits=' + nBits.toString(16) + ')');
    // verifyPoW vs powOk (deterministic; no timestamp involved)
    let libPow = null, indPow = null;
    try { libPow = G.verifyPoW(hex); } catch (e) { if (classifyThrow(e) === 'NON-ERROR-THROW') viol.push('A: lib verifyPoW non-Error throw'); }
    try { indPow = IND.powOk(hex, nBits); } catch (e) { if (classifyThrow(e) === 'NON-ERROR-THROW') viol.push('A: ind powOk non-Error throw'); }
    if (libPow != null && indPow != null && libPow !== indPow) viol.push('DIFF: PoW lib=' + libPow + ' ind=' + indPow);
    rec.target_lib = libTgt != null ? libTgt.toString(16) : 'throw:' + libThrow;
  }
  return { rec, viol };
}

function runHeadersBin(rng, seed, iter) {
  const c = pick(rng, CORPUS.headersbin);
  const strat = pick(rng, ['byte', 'count', 'anchor', 'truncate', 'trailing', 'short']);
  const b = Buffer.from(c.bytes); let mutation = strat, params = {};
  if (strat === 'short') { const m = mutateBytes(rng, c.bytes.subarray(0, randInt(rng, 40))); return finishBin(c, m.bytes, 'short', {}, seed, iter); }
  if (strat === 'count' && b.length >= 40) { const bad = randInt(rng, 0x7fffffff); b.writeUInt32LE(bad >>> 0, 36); params = { count: bad >>> 0 }; }
  else if (strat === 'anchor' && b.length >= 36) { const at = 4 + randInt(rng, 32); b[at] ^= 0xff; params = { at }; }
  else if (strat === 'truncate') { const at = randInt(rng, b.length + 1); return finishBin(c, b.subarray(0, at), 'truncate', { at }, seed, iter); }
  else if (strat === 'trailing') { return finishBin(c, Buffer.concat([b, Buffer.from([randByte(rng)])]), 'trailing', {}, seed, iter); }
  else { const at = randInt(rng, b.length); b[at] ^= (1 << randInt(rng, 8)); params = { at }; }
  return finishBin(c, b, mutation, params, seed, iter);
}
function finishBin(c, bytes, mutation, params, seed, iter) {
  const rec = { target: 'headers.bin', corpusId: c.id, mutation, params, seed, iter, mutatedLen: bytes.length };
  const viol = [];
  const CP = G.CHECKPOINT;
  let libOk = false, libThrow = null, indOk = false, indThrow = null;
  try { const r = G.verifyHeaderChain(new Uint8Array(bytes), CP); libOk = !!(r && r.hashIndex); } catch (e) { libThrow = classifyThrow(e); if (libThrow === 'NON-ERROR-THROW') viol.push('A: lib verifyHeaderChain non-Error throw'); }
  try { const r = IND.loadChain(bytes); indOk = !!(r && r.hashIndex); } catch (e) { indThrow = classifyThrow(e); if (indThrow === 'NON-ERROR-THROW') viol.push('A: ind loadChain non-Error throw'); }
  if (libOk !== indOk) viol.push('DIFF: loader accept mismatch lib=' + (libOk ? 'load' : 'reject:' + libThrow) + ' ind=' + (indOk ? 'load' : 'reject:' + indThrow));
  rec.lib = libOk ? 'loaded' : 'reject'; rec.ind = indOk ? 'loaded' : 'reject';
  return { rec, viol };
}

// Independent BRC-95 re-verification (the false-accept oracle). Given what BEEF.parse
// ACCEPTED, recompute the three rules ourselves - shares no code with lib/beef.js's
// validateAtomicSubject. Returns null if consistent, else the first violated rule.
function independentAtomicViolation(parsed) {
  if (parsed.atomicSubject == null) return null; // not atomic: nothing to check here
  const txs = parsed.transactions || [];
  const subject = parsed.atomicSubject;
  const byId = {}; txs.forEach(t => { byId[t.txid] = t; });
  if (!byId[subject]) return 'subject-not-present';
  if (!txs.length || txs[txs.length - 1].txid !== subject) return 'subject-not-last';
  // reachability: subject + transitive parents present in the container
  const reach = {}; reach[subject] = true; const stack = [subject]; let steps = 0;
  while (stack.length) {
    if (++steps > 100000) return 'HANG-GUARD'; // bounded; cycles cannot inflate this
    const cur = byId[stack.pop()]; if (!cur) continue;
    (cur.inputs || []).forEach(inp => { const p = inp.prevTxid; if (byId[p] && !reach[p]) { reach[p] = true; stack.push(p); } });
  }
  for (const t of txs) if (!reach[t.txid]) return 'unrelated-tx-included';
  return null;
}

function runBeef(rng, seed, iter) {
  if (!CORPUS.beef.length) return { rec: { target: 'BEEF', note: 'no BEEF corpus' }, viol: [] };
  const c = pick(rng, CORPUS.beef);
  // Structured mutation selection. Some rebuild the atomic wrapper with a hostile subject
  // (targeted BRC-95 attacks); the rest are byte/varint/framing mutations of the valid bytes.
  const strat = pick(rng, ['bytes', 'bytes', 'trunc-boundary', 'varint', 'atomic-subject', 'atomic-marker', 'tx-region']);
  let mutHex, mutation, params = {};
  if (strat === 'atomic-subject' && c.atomic) {
    // rewrap the underlying multi with a hostile subject: wrong (ancestor, not last), absent, or self
    const kind = pick(rng, ['ancestor-not-last', 'absent', 'zero']);
    const multi = CORPUS.beef.find(x => x.id === 'multi-ancestor');
    let subj;
    if (kind === 'ancestor-not-last') subj = BEEF.txidOf(ENV.rawTx); // tx0 is an ancestor, not last
    else if (kind === 'zero') subj = '00'.repeat(32);
    else subj = 'ab'.repeat(32);
    try { mutHex = String(BEEF.wrapAtomic(multi.hex, subj)).toLowerCase(); } catch (_) { mutHex = c.hex; }
    mutation = 'atomic-subject:' + kind; params = { kind, subj: subj.slice(0, 12) };
  } else if (strat === 'atomic-marker' && c.atomic) {
    const b = fromHex(c.hex); if (b.length > 4) b[randInt(rng, 4)] ^= 0xff; // corrupt 0x01010101
    mutHex = toHex(b); mutation = 'atomic-marker-flip'; params = {};
  } else if (strat === 'trunc-boundary') {
    const b = fromHex(c.hex); const at = randInt(rng, b.length + 1); mutHex = toHex(b.subarray(0, at)); mutation = 'trunc'; params = { at };
  } else if (strat === 'varint') {
    const b = fromHex(c.hex); if (b.length) { const at = randInt(rng, b.length); b[at] = pick(rng, [0x00, 0x01, 0xfc, 0xfd, 0xfe, 0xff]); mutHex = toHex(b); } else mutHex = c.hex; mutation = 'varint-byte'; params = {};
  } else if (strat === 'tx-region') {
    const b = fromHex(c.hex); if (b.length > 40) { const at = 40 + randInt(rng, b.length - 40); b[at] ^= (1 << randInt(rng, 8)); mutHex = toHex(b); } else mutHex = c.hex; mutation = 'tx-byte-flip'; params = { };
  } else {
    const mm = mutateBytes(rng, fromHex(c.hex)); mutHex = toHex(mm.bytes); mutation = 'bytes:' + mm.op; params = mm.detail;
  }

  const rec = { target: 'BEEF', corpusId: c.id, mutation, params, seed, iter, mutatedHexHead: mutHex.slice(0, 48) };
  const viol = [];
  let parsed = null, threw = null;
  try { parsed = BEEF.parse(mutHex); }
  catch (e) { threw = classifyThrow(e); if (threw === 'NON-ERROR-THROW') viol.push('A: BEEF non-Error throw'); }

  if (parsed) {
    // Invariant B (structural false-accept): if parse ACCEPTED an atomic BEEF, the BRC-95
    // rules must independently hold. Acceptance while a rule is violated is a false accept.
    const v = independentAtomicViolation(parsed);
    if (v === 'HANG-GUARD') viol.push('A: independent atomic walk hit step guard (possible pathological structure)');
    else if (v) viol.push('B: BEEF.parse ACCEPTED an atomic BEEF that violates BRC-95 (' + v + ')');
    // verifyMined false-accept: any tx reported proven must genuinely have its txid in the
    // referenced bump level-0 (independent recheck; no root-trust needed for this check).
    try {
      const rep = BEEF.verifyMined(parsed, BEEF.verifyMined.UNSAFE_SKIP_ROOT_CHECK);
      for (const p of rep.proven) {
        const bump = parsed.bumps[parsed.transactions.find(t => t.txid === p.txid).bumpIndex];
        const present = bump && bump.path && bump.path[0] && bump.path[0].some(l => l.hash === p.txid);
        if (!present) viol.push('B: verifyMined marked ' + p.txid.slice(0, 12) + ' proven but txid absent from its BUMP level-0');
      }
    } catch (e) { if (classifyThrow(e) === 'NON-ERROR-THROW') viol.push('A: verifyMined non-Error throw'); }
    rec.result = 'parsed(' + parsed.transactions.length + 'tx,atomic=' + (parsed.atomicSubject ? 'y' : 'n') + ')';
  } else {
    rec.result = 'reject:' + threw;
  }
  rec.note = 'BEEF not differentially covered by an independent BEEF parser; oracle = independent BRC-95 re-verification + verifyMined recheck';
  return { rec, viol };
}


// ---- envelope-level Invariant B/C via the independent verify() ------------------------
function runEnvelope(rng, seed, iter) {
  // mutate the bump inside a full envelope and drive the whole verifier
  const env = JSON.parse(JSON.stringify(ENV));
  const m = mutateHexString(rng, env.bump);
  env.bump = m.hex;
  const rec = { target: 'Envelope', corpusId: 'real-envelope', mutation: 'bump:' + m.op, params: m.detail, seed, iter };
  const viol = [];
  let out = null, threw = null;
  try { const r = IND.verify(env, { bindRawTx: true }); out = r.outcome; }
  catch (e) { threw = classifyThrow(e); viol.push('A: independent verify() threw instead of typed outcome (' + threw + ')'); }
  if (out != null) {
    // C: typed outcome membership
    const known = new Set(Object.values(IND.OUT));
    if (!known.has(out)) viol.push('C: unknown outcome ' + out);
    // B: if accepted, the binding must independently hold
    if (ACCEPT.has(out) && !bindingHolds(env)) viol.push('B: FALSE ACCEPT - verify()=' + out + ' but txid->root->header binding does not hold');
  }
  rec.outcome = out || ('throw:' + threw);
  return { rec, viol };
}

const RUNNERS = [runBump, runHeader, runHeadersBin, runEnvelope, runBeef];
const RUNNER_NAMES = ['BUMP', 'Header', 'headers.bin', 'Envelope', 'BEEF'];

// pick a runner deterministically; skip BEEF if no corpus
function runnerFor(rng) {
  const avail = CORPUS.beef.length ? RUNNERS : RUNNERS.slice(0, 4);
  const idx = randInt(rng, avail.length);
  return { idx, run: avail[idx] };
}

function runIteration(seed, i) {
  const rng = iterationRng(seed, i);
  const { idx, run } = runnerFor(rng);
  const res = run(rng, seed, i);
  res.rec.runner = RUNNER_NAMES[idx];
  return res;
}

// ---- CLI -----------------------------------------------------------------------------
function arg(name, def) { const k = process.argv.indexOf(name); return k >= 0 && process.argv[k + 1] != null ? process.argv[k + 1] : def; }
const seed = (parseInt(arg('--seed', '' + ((Date.now() ^ (process.pid << 8)) >>> 0)), 10) >>> 0);
const iters = parseInt(arg('--iters', '1000'), 10);
const replay = process.argv.indexOf('--replay') >= 0 ? parseInt(arg('--replay', '0'), 10) : null;

if (replay != null) {
  const res = runIteration(seed, replay);
  console.log('REPLAY seed=' + seed + ' iteration=' + replay);
  console.log(JSON.stringify(res.rec, null, 2));
  console.log('violations:', res.viol.length ? res.viol : 'none');
  // determinism check: run again, compare
  const res2 = runIteration(seed, replay);
  console.log('deterministic:', JSON.stringify(res.rec) === JSON.stringify(res2.rec));
  process.exit(res.viol.length ? 1 : 0);
}

console.log('Merkle Envelope Tools - deterministic parser fuzz\n');
console.log('Seed:       ' + seed);
console.log('Iterations: ' + iters + '\n');

const counts = {}; RUNNER_NAMES.forEach(n => counts[n] = 0);
let exceptions = 0, falseAccepts = 0, divergences = 0, nondeterminism = 0, typedViol = 0;
const failures = [];

for (let i = 0; i < iters; i++) {
  let res;
  try { res = runIteration(seed, i); }
  catch (e) { exceptions++; failures.push({ seed, iter: i, fatal: String(e && e.stack || e) }); continue; }
  counts[res.rec.runner] = (counts[res.rec.runner] || 0) + 1;
  // Invariant D: same iteration reproduces
  const res2 = runIteration(seed, i);
  if (JSON.stringify(res.rec) !== JSON.stringify(res2.rec)) { nondeterminism++; res.viol.push('D: non-deterministic'); }
  for (const v of res.viol) {
    if (v.startsWith('A:')) exceptions++;
    else if (v.startsWith('B:')) falseAccepts++;
    else if (v.startsWith('C:')) typedViol++;
    else if (v.startsWith('DIFF:')) divergences++;
    else if (v.startsWith('D:')) { /* counted above */ }
  }
  if (res.viol.length) failures.push({ ...res.rec, violations: res.viol });
}

const pad = (n) => String(n).padStart(9);
console.log('Cases per target:');
for (const n of RUNNER_NAMES) if (counts[n]) console.log('  ' + n.padEnd(14) + pad(counts[n]));
console.log('');
console.log('Exceptions (Invariant A):   ' + exceptions);
console.log('False acceptances (Inv B):  ' + falseAccepts);
console.log('Typed-outcome viol (Inv C): ' + typedViol);
console.log('Outcome divergences (DIFF): ' + divergences);
console.log('Non-determinism (Inv D):    ' + nondeterminism);
console.log('');

if (failures.length) {
  const outDir = path.join(ROOT, 'test', 'fuzz-failures');
  try { fs.mkdirSync(outDir, { recursive: true }); fs.writeFileSync(path.join(outDir, seed + '.json'), JSON.stringify(failures.slice(0, 200), null, 2)); } catch (_) {}
  console.log('FIRST FAILURES (reproduce with --seed ' + seed + ' --replay <iter>):');
  for (const f of failures.slice(0, 10)) console.log('  iter ' + f.iter + ' [' + (f.runner || 'fatal') + '/' + (f.mutation || '') + '] ' + JSON.stringify(f.violations || f.fatal));
  console.log('\nRESULT: FAIL (' + failures.length + ' case(s); records in test/fuzz-failures/' + seed + '.json)');
  process.exit(1);
}
console.log('RESULT: PASS  (no exceptions, false-accepts, typed-outcome violations, divergences, or non-determinism');
console.log('              in the ' + iters + ' mutations tested at this seed - not a claim beyond what was tested)');
process.exit(0);
