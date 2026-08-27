'use strict';
/*
 * headers-node-independent — a from-the-spec reimplementation of the Merkle-Envelope
 * verification semantics, written ONLY from VERIFICATION-SEMANTICS-SPEC.md plus public
 * standards (Bitcoin 80-byte header, SHA-256d, compact-target/nBits, BRC-74 BUMP). No
 * reference implementation file (lib/*.js, *.html, headers-node/verify.js) was opened while
 * writing this.
 *
 * HONEST CEILING: the same author wrote the spec, the reference, and headers-node. Process
 * independence (not opening reference files) is real; author independence is not achievable.
 * Structural resemblance to headers-node is therefore expected and is NOT evidence of
 * cross-implementer convergence. See the blindness audit in the task report.
 *
 * Sole primitive dependency: Node crypto (SHA-256). Everything else derived here.
 */
const nodeCrypto = require('crypto');

// ---- Policy constants (from spec §E / §O — present in the spec text) ----------------
const CHECKPOINT = { height: 939999,
  hash: '00000000000000000e7aea9b454b4acc945e6ae5883ca7254809e538bb54ef12',
  nBits: 0x18227b71 };
const TOLERANCE = 8;                 // §E-2 difficulty-floor multiplier
const GENESIS_TS = 1231006505;       // §E-3
const MAX_FUTURE = 7200;             // §E-3
const MAX_DEPTH = 32;                // §D
const SPEC_VERSION = 'mev-1';        // §K framing (value arbitrary; only stability matters)

// Trust-boundary hardening: a module-private WeakSet of loader-produced indexes. UNFORGEABLE —
// unlike a Symbol/property (which Object.getOwnPropertySymbols can reflect and copy), WeakSet
// membership cannot be observed or added to without a reference to the set, which is never
// exported. verify() treats an index as authoritative for a VERIFIED inclusion verdict ONLY if
// it is in this set (came from loadChain) or the caller passes an explicit, documented
// trustIndex:true assertion. An unanchored raw Map can therefore never establish trusted
// membership. Production explorer/verifier already enforce this structurally (their index is a
// closure variable assigned only from verifyHeaderChain output); this makes the same contract
// explicit in the parameterized reimplementation API.
const ANCHORED_INDEXES = new WeakSet();

// ---- Outcome vocabulary (§F) --------------------------------------------------------
const OUT = {
  VERIFIED: 'VERIFIED', VERIFIED_ISOLATION: 'VERIFIED-ISOLATION', FAILED: 'FAILED',
  NOT_ESTABLISHED: 'NOT-ESTABLISHED', POLICY_REJECTED: 'POLICY-REJECTED',
  MALFORMED: 'MALFORMED', INDETERMINATE: 'INDETERMINATE'
};
const SCOPE_ANTICLAIMS = [           // §J permanently not-attempted
  { id: 'most-work-chain', scope: 'not-attempted' },
  { id: 'current-spend-status', scope: 'not-attempted' }
];

// ---- Error taxonomy: separate input problems from evaluation failures (§I) ----------
class Malformed extends Error { constructor(m){ super(m); this.kind='malformed'; } }
class Contradicted extends Error { constructor(m){ super(m); this.kind='failed'; } }   // §C claim contradicted
class PolicyReject extends Error { constructor(m){ super(m); this.kind='policy'; } }    // §E
class EvalFailure extends Error { constructor(m){ super(m); this.kind='eval'; } }       // §I INDETERMINATE

// §I: consensus/policy operations run through guard(); any *unexpected* throw becomes an
// EvalFailure (→ INDETERMINATE). Our own typed errors pass through unchanged so a real
// FAILED/MALFORMED/POLICY is not masked as INDETERMINATE.
function guard(fn) {
  try { return fn(); }
  catch (e) {
    if (e instanceof Malformed || e instanceof Contradicted ||
        e instanceof PolicyReject || e instanceof EvalFailure) throw e;
    throw new EvalFailure((e && e.message) || String(e));
  }
}

// ---- byte / hash helpers (public: SHA256d, hex, LE<->display) -----------------------
function assertHex(s, what) {
  if (typeof s !== 'string' || s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s))
    throw new Malformed('invalid hex: ' + (what || ''));
}
function toBytes(hex, what) { assertHex(hex, what); return Buffer.from(hex, 'hex'); }
function sha256(b) { return nodeCrypto.createHash('sha256').update(b).digest(); }
function sha256d(b) { return sha256(sha256(b)); }
function rev(hex) { return Buffer.from(hex, 'hex').reverse().toString('hex'); }
function low(x) { return (x == null ? '' : String(x)).toLowerCase(); }

// ---- 80-byte header (§C byte layout) ------------------------------------------------
function parseHeader(headerHex) {
  if (typeof headerHex !== 'string' || headerHex.length !== 160)
    throw new Malformed('header must be exactly 80 bytes');
  const b = toBytes(headerHex, 'header');
  return {
    merkleRootField: rev(b.slice(36, 68).toString('hex')), // LE field -> display
    time: b.readUInt32LE(68),
    bits: b.readUInt32LE(72),
    prevBlock: rev(b.slice(4, 36).toString('hex')),        // LE -> display
    bytes: b
  };
}
function headerHashDisplay(headerHex) {
  return Buffer.from(sha256d(toBytes(headerHex, 'header'))).reverse().toString('hex');
}
// §C: compact "nBits" -> target (public consensus algorithm)
function targetFromBits(bits) {
  const exp = bits >>> 24, mant = BigInt(bits & 0x007fffff);
  return exp >= 3 ? mant << BigInt(8 * (exp - 3)) : mant >> BigInt(8 * (3 - exp));
}
// §C: SHA256d(header) as LITTLE-ENDIAN 256-bit int <= target.
// Natural bytes reversed == display hex, and BigInt(display-hex) reads those natural bytes
// little-endian, which is exactly the required interpretation.
function powOk(headerHex, bits) {
  return BigInt('0x' + headerHashDisplay(headerHex)) <= targetFromBits(bits);
}

// ---- legacy Merkle fold (§B byte order: siblings NATURAL/verbatim; pos = sibling side) --
function rootFromLegacy(txidDisplay, proof) {
  if (!Array.isArray(proof)) throw new Malformed('proof must be an array');
  if (proof.length > MAX_DEPTH) throw new Malformed('proof depth exceeds 32');
  let acc = toBytes(rev(txidDisplay), 'txid'); // display -> natural
  for (const step of proof) {
    if (!step || typeof step.hash !== 'string' || step.hash.length !== 64)
      throw new Malformed('proof step hash length');
    const sib = toBytes(step.hash, 'sibling'); // NATURAL, verbatim (§B)
    const p = String(step.pos || '').toUpperCase();
    if (p !== 'L' && p !== 'R') throw new Malformed('proof step pos must be L or R');
    const left = (p === 'L') ? sib : acc;      // pos = sibling's side
    const right = (p === 'L') ? acc : sib;
    acc = sha256d(Buffer.concat([left, right]));
  }
  return Buffer.from(acc).reverse().toString('hex'); // natural -> display
}

// ---- BRC-74 BUMP (public standard; spec §B/§D reference it) --------------------------
// Format: varint blockHeight, uint8 treeHeight, then per level: varint nLeaves, then each
// leaf: varint offset, uint8 flags (bit0=duplicate, bit1=clientTxid), 32-byte hash unless dup.
function readVarint(buf, c) {
  const f = buf[c.p++];
  if (f < 0xfd) return f;
  if (f === 0xfd) { const v = buf.readUInt16LE(c.p); c.p += 2; return v; }
  if (f === 0xfe) { const v = buf.readUInt32LE(c.p); c.p += 4; return v; }
  const v = Number(buf.readBigUInt64LE(c.p)); c.p += 8; return v;
}
function parseBump(bumpHex) {
  const buf = toBytes(bumpHex, 'bump');
  const c = { p: 0 };
  readVarint(buf, c);                       // blockHeight (unused for root)
  const treeHeight = buf[c.p++];
  if (treeHeight > MAX_DEPTH) throw new Malformed('bump tree height exceeds 32');
  const levels = [];
  for (let h = 0; h < treeHeight; h++) {
    const n = readVarint(buf, c);
    const leaves = [];
    for (let i = 0; i < n; i++) {
      const offset = readVarint(buf, c);
      const flags = buf[c.p++];
      const dup = (flags & 1) !== 0;
      let hash = null;
      if (!dup) {
        if (c.p + 32 > buf.length) throw new Malformed('bump truncated leaf');
        hash = Buffer.from(buf.slice(c.p, c.p + 32)).reverse().toString('hex'); // -> display
        c.p += 32;
      }
      leaves.push({ offset, dup, hash });
    }
    levels.push(leaves);
  }
  if (c.p !== buf.length) throw new Malformed('bump trailing bytes');
  return { levels, treeHeight };
}
function rootFromBump(bump, txidDisplay) {
  const l0 = bump.levels[0] || [];
  // Any level-0 leaf hash is a txid in the block's tx tree (BRC-74). Match by hash.
  const leaf = l0.find(x => x.hash && low(x.hash) === low(txidDisplay));
  if (!leaf) throw new Contradicted('txid not present in BUMP');
  let index = leaf.offset;
  let acc = toBytes(rev(txidDisplay), 'txid');
  for (let h = 0; h < bump.treeHeight; h++) {
    const sibOff = index ^ 1;
    const level = bump.levels[h] || [];
    const sib = level.find(x => x.offset === sibOff);
    if (!sib) throw new Malformed('bump missing sibling at level ' + h);
    const sibNat = sib.dup ? acc : toBytes(rev(sib.hash), 'bump-sib');
    const left = (index & 1) ? sibNat : acc;
    const right = (index & 1) ? acc : sibNat;
    acc = sha256d(Buffer.concat([left, right]));
    index >>= 1;
  }
  return Buffer.from(acc).reverse().toString('hex');
}

// ---- header policy (§E-2 floor + §E-3 timestamp) -> POLICY-REJECTED ------------------
function checkpointTarget() { return targetFromBits(CHECKPOINT.nBits); }
function floorTarget() { return checkpointTarget() * BigInt(TOLERANCE); }
function headerPolicy(hdr) {
  if (targetFromBits(hdr.bits) > floorTarget()) return { ok: false, reason: 'sub-floor header' };
  if (hdr.time < GENESIS_TS) return { ok: false, reason: 'timestamp before genesis' };
  if (hdr.time > Math.floor(Date.now() / 1000) + MAX_FUTURE) return { ok: false, reason: 'timestamp too far in future' };
  return { ok: true };
}

// ---- chain loader (§O): headers.bin -> checkpoint-anchored hashIndex -----------------
function loadChain(bytes, opts) {
  opts = opts || {};
  const requireCk = opts.requireCheckpoint !== false;
  if (bytes.length < 40) throw new Malformed('headers.bin < 40 bytes');
  const anchorHeight = bytes.readUInt32LE(0);
  const anchorHash = bytes.slice(4, 36).toString('hex');   // stored display (§O)
  const count = bytes.readUInt32LE(36);
  if (bytes.length < 40 + count * 80) throw new Malformed('headers.bin truncated');
  if (requireCk && (anchorHeight !== CHECKPOINT.height || low(anchorHash) !== low(CHECKPOINT.hash)))
    throw new PolicyReject('chain not anchored at checkpoint');
  const hashIndex = new Map();
  const seen = new Set();
  const floor = floorTarget();
  let prev = anchorHash, off = 40, tipHash = anchorHash, tipHeight = anchorHeight;
  for (let i = 0; i < count; i++) {
    const height = anchorHeight + 1 + i;
    const hex = bytes.slice(off, off + 80).toString('hex');
    const hdr = parseHeader(hex);
    if (low(hdr.prevBlock) !== low(prev)) throw new Contradicted('chain break at ' + height);
    if (!powOk(hex, hdr.bits)) throw new Contradicted('invalid PoW at ' + height);
    if (targetFromBits(hdr.bits) > floor) throw new PolicyReject('sub-floor header at ' + height);
    const hash = headerHashDisplay(hex);
    if (seen.has(low(hash))) throw new Malformed('duplicate header hash at ' + height);
    seen.add(low(hash));
    hashIndex.set(low(hash), height);
    prev = hash; tipHash = hash; tipHeight = height; off += 80;
  }
  // Register the index as loader-anchored (unforgeable WeakSet membership) so verify() can
  // distinguish a loader-produced, checkpoint-anchored index from an arbitrary caller-built Map.
  ANCHORED_INDEXES.add(hashIndex);
  return { hashIndex, tipHeight, tipHash, anchor: { height: anchorHeight, hash: anchorHash } };
}

// ---- evidence digest (§K): verdict-relevant identity, absent != empty ---------------
function frame(s) { s = (s == null ? '' : String(s)); return s.length + ':' + s; }
function opt(name, v) { return frame(name) + (v == null ? '\x00' : '\x01' + frame(String(v))); }
function evidenceDigest(env) {
  env = env || {};
  const ck = CHECKPOINT.height + '|' + low(CHECKPOINT.hash) + '|' + (CHECKPOINT.nBits >>> 0).toString(16);
  const proof = Array.isArray(env.proof) ? env.proof : null;
  const proofStr = proof == null ? '\x00'
    : '\x01' + frame(String(proof.length)) + proof.map(p => frame(low(p.hash)) + frame(low(p.pos))).join('');
  const s = [
    frame('ver'), frame(SPEC_VERSION),
    frame('ckpt'), frame(ck),
    frame('tol'), frame(String(TOLERANCE)),
    frame('txid'), frame(low(env.txid)),
    frame('hdr'), frame(low(env.blockHeader)),
    opt('rawTx', env.rawTx == null ? null : low(env.rawTx)),
    opt('bump', env.bump == null ? null : low(env.bump)),
    opt('beef', env.beef == null ? null : low(env.beef)),
    opt('atomicBeef', env.atomicBeef == null ? null : low(env.atomicBeef)),
    frame('proof'), proofStr
  ].join('');
  return sha256(Buffer.from(s, 'binary')).toString('hex');
}

// ---- classification (§G precedence) -------------------------------------------------
function classify(sig) {
  if (sig.eval) return OUT.INDETERMINATE;
  if (sig.malformed) return OUT.MALFORMED;
  if (sig.failed) return OUT.FAILED;
  if (sig.policy) return OUT.POLICY_REJECTED;
  if (sig.established) return sig.chainLoaded ? (sig.included ? OUT.VERIFIED : OUT.FAILED)
                                              : OUT.VERIFIED_ISOLATION;
  return OUT.NOT_ESTABLISHED;
}

/*
 * verify(envelope, opts)
 *   opts.chainHashIndex : Map<displayHashLower, height> (from loadChain) or null
 *   opts.bindRawTx      : enforce txid == SHA256d(rawTx) (verifier/chain scope). default true.
 */
function verify(envelope, opts) {
  opts = opts || {};
  const bindRawTx = opts.bindRawTx !== false;
  const suppliedIndex = opts.chainHashIndex || (opts.chain && opts.chain.hashIndex) || null;
  // Trust boundary: an index establishes membership ONLY if it is loader-anchored (carries the
  // unforgeable ANCHORED marker) or the caller explicitly asserts trustIndex:true. An
  // unanchored raw Map is refused for membership and the verdict fails closed to isolation.
  const indexTrusted = !!suppliedIndex &&
    (ANCHORED_INDEXES.has(suppliedIndex) || opts.trustIndex === true);
  const chain = indexTrusted ? suppliedIndex : null;
  const indexRefused = !!suppliedIndex && !indexTrusted;
  const advisories = [];
  const claims = {};
  const result = {
    outcome: null, valid: false, claims, advisories,
    chainInclusion: { status: chain ? 'pending' : (indexRefused ? 'refused-unanchored' : 'unknown'), height: null },
    scope: SCOPE_ANTICLAIMS.map(s => ({ id: s.id, scope: s.scope })),
    evidenceDigest: null, diagnostic: null
  };
  try { result.evidenceDigest = evidenceDigest(envelope || {}); } catch (_) {}

  const sig = { eval:false, malformed:false, failed:false, policy:false,
                established:false, chainLoaded: !!chain, included:false };
  try {
    if (!envelope || typeof envelope !== 'object') throw new Malformed('envelope not an object');
    // §B required fields (GAP-A): txid + blockHeader. vout NOT gated (SPEC AMBIGUITY: treated advisory).
    if (envelope.blockHeader == null || envelope.blockHeader === '')
      throw new Malformed('blockHeader required');
    if (envelope.txid == null || envelope.txid === '')
      throw new Malformed('txid required');

    const hdr = parseHeader(envelope.blockHeader);              // bad hex/len -> Malformed
    const blockHash = headerHashDisplay(envelope.blockHeader);
    result.blockHash = blockHash;

    // §C-1 txid<->rawTx binding (verifier/chain). rawTx absent in bind mode -> skip (AMBIGUITY).
    if (bindRawTx && envelope.rawTx != null) {
      let computed;
      try { computed = Buffer.from(sha256d(toBytes(envelope.rawTx, 'rawTx'))).reverse().toString('hex'); }
      catch (e) { throw new Malformed('rawTx not decodable'); }
      claims.txidBinding = (low(computed) === low(envelope.txid));
      if (!claims.txidBinding) throw new Contradicted('txid != SHA256d(rawTx)');
    }

    // §C-3 PoW (consensus dependency -> guard so an internal fault is INDETERMINATE, not FAILED)
    claims.pow = guard(() => powOk(envelope.blockHeader, hdr.bits));
    if (!claims.pow) throw new Contradicted('proof-of-work invalid');

    // §C-2 Merkle root binding. Proof selection order (§B): bump -> beef/atomicBeef -> legacy.
    let root;
    if (envelope.bump != null) {
      root = rootFromBump(parseBump(envelope.bump), envelope.txid);
    } else if (envelope.beef != null || envelope.atomicBeef != null) {
      // SPEC DEPENDENCY: BEEF/Atomic byte format lives in BRC-62/95, not the spec text.
      // Not implemented here; treated as an evaluation gap so it can never falsely VERIFY.
      throw new EvalFailure('BEEF/atomicBeef parsing not implemented in this independent build');
    } else {
      root = rootFromLegacy(envelope.txid, envelope.proof || []); // absent -> empty depth-0 (§B)
    }
    claims.merkleRoot = (low(root) === low(hdr.merkleRootField));
    if (!claims.merkleRoot) throw new Contradicted('merkle root != header root field');

    // §E policy: floor + timestamp -> POLICY-REJECTED
    const pol = guard(() => headerPolicy(hdr));
    claims.policy = pol.ok;
    if (!pol.ok) throw new PolicyReject(pol.reason);

    sig.established = true; // all present cryptographic + policy claims hold

    // §C-4 chain inclusion on the COMPUTED hash
    if (chain) {
      const hit = guard(() => chain.has(low(blockHash)));  // broken index -> throws -> INDETERMINATE
      if (hit) { result.chainInclusion = { status: 'verified', height: guard(() => chain.get(low(blockHash))) }; sig.included = true; }
      else { result.chainInclusion = { status: 'not_in_chain', height: null }; throw new Contradicted('not_in_chain'); }
    } else {
      result.chainInclusion = { status: indexRefused ? 'refused-unanchored' : 'unknown', height: null };
    }

    // §H advisory axis (never changes outcome)
    if (indexRefused)
      advisories.push({ id: 'chain-index-refused', detail: 'supplied chain index is not loader-anchored; inclusion not established (isolation)' });
    if (typeof envelope.confirmations === 'number' && envelope.confirmations < 6)
      advisories.push({ id: 'low-confirmations', detail: envelope.confirmations });

    result.outcome = classify(sig);
    result.valid = (result.outcome === OUT.VERIFIED || result.outcome === OUT.VERIFIED_ISOLATION);
    return result;
  } catch (e) {
    if (e instanceof EvalFailure)        { sig.eval = true;      result.diagnostic = 'eval: ' + e.message; }
    else if (e instanceof Malformed)     { sig.malformed = true; result.diagnostic = 'malformed: ' + e.message; }
    else if (e instanceof PolicyReject)  { sig.policy = true;    result.diagnostic = 'policy: ' + e.message; }
    else if (e instanceof Contradicted)  { sig.failed = true;    result.diagnostic = 'failed: ' + e.message; }
    else                                 { sig.eval = true;      result.diagnostic = 'unexpected: ' + (e && e.message); }
    result.outcome = classify(sig);
    result.valid = false;             // §I: an evaluation error can never be VERIFIED
    return result;
  }
}

module.exports = {
  verify, loadChain, evidenceDigest, OUT, CHECKPOINT, TOLERANCE,
  parseHeader, headerHashDisplay, targetFromBits, powOk,
  rootFromLegacy, parseBump, rootFromBump, headerPolicy,
  Malformed, Contradicted, PolicyReject, EvalFailure
};
