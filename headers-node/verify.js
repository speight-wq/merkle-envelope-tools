'use strict';
/*
 * headers-node — an INDEPENDENT implementation of the Merkle Envelope verification
 * semantics, written from VERIFICATION-SEMANTICS-SPEC.md and public standards
 * (Bitcoin block-header format, BRC-74 BUMP, double-SHA256, compact-target/nBits),
 * NOT from lib/headers.js. It shares no code with the reference implementation.
 *
 * Independence caveat (recorded honestly): the reference implementation and this file
 * were written by the same author. This experiment therefore tests whether the SPEC is
 * sufficient to reproduce the semantics — it is not evidence of two unrelated developers.
 *
 * Sole primitive dependency: Node's crypto (SHA-256). Everything else is derived here.
 */
const crypto = require('crypto');

// ---- Policy constants (from the frozen contract §E) --------------------------------
const CHECKPOINT = {
  height: 939999,
  hash: '00000000000000000e7aea9b454b4acc945e6ae5883ca7254809e538bb54ef12',
  nBits: 0x18227b71
};
const TOLERANCE = 8;              // difficulty-floor multiplier (§E)
const SPEC_VERSION = '1';         // evidence-digest framing (§K)
const MAX_DEPTH = 32;             // structural bound (§D)
const GENESIS_TIMESTAMP = 1231006505; // header timestamp policy (§E): Bitcoin genesis (2009-01-03)
const MAX_FUTURE_SECONDS = 7200;      // header timestamp policy (§E): 2h ahead of wall clock

const OUTCOME = {
  VERIFIED: 'VERIFIED',
  VERIFIED_ISOLATION: 'VERIFIED-ISOLATION',
  FAILED: 'FAILED',
  NOT_ESTABLISHED: 'NOT-ESTABLISHED',
  POLICY_REJECTED: 'POLICY-REJECTED',
  MALFORMED: 'MALFORMED',
  INDETERMINATE: 'INDETERMINATE'
};

// Permanent scope boundary (§J) — never established in any mode.
const CLAIMS_NOT_ESTABLISHED = [
  { id: 'most-work-chain', scope: 'not-attempted' },
  { id: 'current-spend-status', scope: 'not-attempted' }
];

// ---- Error taxonomy: distinguish input problems from evaluation failures (§I) -------
class MalformedInput extends Error { constructor(m){ super(m); this.name = 'MalformedInput'; } }
class EvaluationError extends Error { constructor(m){ super(m); this.name = 'EvaluationError'; } }
// A verification claim was evaluated and contradicted (§F FAILED).
class VerificationFailure extends Error { constructor(m){ super(m); this.name = 'VerificationFailure'; } }
// A declared local policy rejected well-formed valid evidence (§F POLICY-REJECTED).
class PolicyRejection extends Error { constructor(m){ super(m); this.name = 'PolicyRejection'; } }

// evalDep: any throw from a consensus/policy dependency is an evaluation failure,
// EXCEPT the semantic exceptions we raise deliberately (which must propagate as-is).
function evalDep(fn) {
  try { return fn(); }
  catch (e) {
    if (e instanceof MalformedInput || e instanceof EvaluationError ||
        e instanceof VerificationFailure || e instanceof PolicyRejection) throw e;
    throw new EvaluationError(e && e.message ? e.message : String(e));
  }
}

// ---- Byte / hash primitives (public: double-SHA256, hex, LE<->display) --------------
function isHex(s){ return typeof s === 'string' && s.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(s); }
function hexToBytes(hex){
  if (!isHex(hex)) throw new MalformedInput('invalid hex');
  return Buffer.from(hex, 'hex');
}
function sha256(buf){ return crypto.createHash('sha256').update(buf).digest(); }
function sha256d(buf){ return sha256(sha256(buf)); }
function reverseHex(hex){ return Buffer.from(hex, 'hex').reverse().toString('hex'); }
function lc(x){ return (x == null ? '' : String(x)).toLowerCase(); }

// ---- Block header (public 80-byte format) ------------------------------------------
// version(4) prevHash(32) merkleRoot(32) time(4) bits(4) nonce(4) — all little-endian.
function parseHeader(headerHex){
  if (typeof headerHex !== 'string' || headerHex.length !== 160) throw new MalformedInput('header must be 80 bytes');
  const b = hexToBytes(headerHex); // throws MalformedInput on bad hex
  return {
    merkleRootDisplay: reverseHex(b.slice(36, 68).toString('hex')), // stored LE -> display
    timestamp: b.readUInt32LE(68),
    bits: b.readUInt32LE(72),
    bytes: b
  };
}
function hashHeaderDisplay(headerHex){
  const h = sha256d(hexToBytes(headerHex));            // natural (LE) 32 bytes
  return Buffer.from(h).reverse().toString('hex');     // display (big-endian)
}
// compact "nBits" -> 256-bit target (public algorithm).
function targetFromBits(bits){
  const exponent = bits >>> 24;
  const mantissa = bits & 0x007fffff;
  let target;
  if (exponent <= 3) target = BigInt(mantissa) >> BigInt(8 * (3 - exponent));
  else target = BigInt(mantissa) << BigInt(8 * (exponent - 3));
  return target;
}
function headerHashValue(headerHex){
  // PoW compares the double-SHA256 as a little-endian 256-bit integer against target.
  const h = sha256d(hexToBytes(headerHex));            // natural byte order
  return BigInt('0x' + Buffer.from(h).reverse().toString('hex'));
}
function powValid(headerHex, bits){
  return headerHashValue(headerHex) <= targetFromBits(bits);
}

// ---- Legacy Merkle proof: fold from txid up to the root ----------------------------
// Convention (spec §B/§C, clarified via the conformance experiment): the txid is supplied
// in DISPLAY (big-endian) order and reversed to natural for hashing; each proof step `hash`
// is supplied in NATURAL (internal) byte order and used as-is. `pos` is the SIBLING's side.
function merkleRootFromLegacy(txidDisplay, proof){
  if (!Array.isArray(proof)) throw new MalformedInput('proof must be an array');
  if (proof.length > MAX_DEPTH) throw new MalformedInput('proof depth exceeds bound');
  let acc = hexToBytes(reverseHex(txidDisplay)); // txid display -> natural
  for (const step of proof){
    if (!step || typeof step.hash !== 'string' || !isHex(step.hash) || step.hash.length !== 64)
      throw new MalformedInput('proof step hash invalid');
    const pos = String(step.pos || '').toUpperCase();
    if (pos !== 'L' && pos !== 'R') throw new MalformedInput('proof step pos invalid');
    const sib = hexToBytes(step.hash); // natural byte order, as supplied
    const left = (pos === 'L') ? sib : acc;
    const right = (pos === 'L') ? acc : sib;
    acc = sha256d(Buffer.concat([left, right]));
  }
  return Buffer.from(acc).reverse().toString('hex'); // -> display
}

// ---- BRC-74 BUMP: parse hex, reconstruct root for a target txid --------------------
function readVarInt(buf, o){
  const first = buf[o.p++];
  if (first < 0xfd) return first;
  if (first === 0xfd){ const v = buf.readUInt16LE(o.p); o.p += 2; return v; }
  if (first === 0xfe){ const v = buf.readUInt32LE(o.p); o.p += 4; return v; }
  const v = Number(buf.readBigUInt64LE(o.p)); o.p += 8; return v;
}
function parseBump(bumpHex){
  const buf = hexToBytes(bumpHex);
  const o = { p: 0 };
  readVarInt(buf, o);                 // block height (unused for root)
  const treeHeight = buf[o.p++];
  if (treeHeight > MAX_DEPTH) throw new MalformedInput('bump tree height exceeds bound');
  const levels = [];
  for (let h = 0; h < treeHeight; h++){
    const n = readVarInt(buf, o);
    const leaves = [];
    for (let i = 0; i < n; i++){
      const offset = readVarInt(buf, o);
      const flags = buf[o.p++];
      const dup = (flags & 1) !== 0;
      const isTxid = (flags & 2) !== 0;
      let hash = null;
      if (!dup){
        if (o.p + 32 > buf.length) throw new MalformedInput('bump truncated');
        hash = Buffer.from(buf.slice(o.p, o.p + 32)).reverse().toString('hex'); // -> display
        o.p += 32;
      }
      leaves.push({ offset, dup, isTxid, hash });
    }
    levels.push(leaves);
  }
  if (o.p !== buf.length) throw new MalformedInput('bump has trailing bytes');
  return { levels, treeHeight };
}
function merkleRootFromBump(bump, txidDisplay){
  const { levels, treeHeight } = bump;
  const l0 = levels[0] || [];
  // Any level-0 leaf hash is a txid in the block's tx-merkle tree; the txid flag only marks
  // which leaves were the bump's "client" txids. Match by hash so a proof for an unflagged
  // co-leaf txid also reconstructs (BRC-74 published vector exercises this).
  const leaf = l0.find(x => x.hash && lc(x.hash) === lc(txidDisplay));
  if (!leaf) throw new VerificationFailure('txid not present in BUMP');
  let index = leaf.offset;
  let acc = hexToBytes(reverseHex(txidDisplay));
  for (let h = 0; h < treeHeight; h++){
    const siblingOffset = index ^ 1;
    const level = levels[h] || [];
    let sib = level.find(x => x.offset === siblingOffset);
    let sibNat;
    if (!sib) throw new MalformedInput('bump missing sibling at level ' + h);
    sibNat = sib.dup ? acc : hexToBytes(reverseHex(sib.hash));
    const left = (index & 1) ? sibNat : acc;
    const right = (index & 1) ? acc : sibNat;
    acc = sha256d(Buffer.concat([left, right]));
    index = index >> 1;
  }
  return Buffer.from(acc).reverse().toString('hex');
}

// ---- Difficulty floor (policy) -----------------------------------------------------
function checkpointTarget(){ return targetFromBits(CHECKPOINT.nBits); }
function floorTarget(){ return checkpointTarget() * BigInt(TOLERANCE); }
// ---- Header policy (§E): difficulty floor + timestamp sanity -----------------------
// Mirrors the reference's validateHeaderDifficulty CONTRACT (floor + timestamp), returning
// {valid, reason}. A violation is POLICY-REJECTED. The future-timestamp bound uses wall
// clock (the only non-deterministic input; never triggers for historical headers).
function headerPolicy(headerHex){
  const h = parseHeader(headerHex);
  if (targetFromBits(h.bits) > floorTarget()) return { valid:false, reason:'below difficulty floor' };
  if (h.timestamp < GENESIS_TIMESTAMP) return { valid:false, reason:'timestamp before genesis' };
  if (h.timestamp > Math.floor(Date.now()/1000) + MAX_FUTURE_SECONDS) return { valid:false, reason:'timestamp too far in future' };
  return { valid:true };
}
function difficultyFloorOk(bits){ return targetFromBits(bits) <= floorTarget(); }

// ---- Evidence digest (§K): verdict-relevant identity, absent != empty --------------
function frame(s){ s = (s == null ? '' : String(s)); return s.length + ':' + s; }
function frameOpt(name, val){ return frame(name) + (val == null ? '0' : '1' + frame(String(val))); }
function evidenceIdentity(env){
  const cp = CHECKPOINT.height + '/' + lc(CHECKPOINT.hash) + '/' + (CHECKPOINT.nBits >>> 0).toString(16);
  const proof = Array.isArray(env.proof) ? env.proof : [];
  const proofCanon = proof.map(p => frame(lc(p.hash)) + frame(lc(p.pos))).join('');
  const s =
    frame('v') + frame(SPEC_VERSION) +
    frame('checkpoint') + frame(cp) +
    frame('tolerance') + frame(String(TOLERANCE)) +
    frame('txid') + frame(lc(env.txid)) +
    frame('header') + frame(lc(env.blockHeader)) +
    frameOpt('rawTx', env.rawTx == null ? undefined : lc(env.rawTx)) +
    frameOpt('bump', env.bump == null ? undefined : lc(env.bump)) +
    frameOpt('beef', env.beef == null ? undefined : lc(env.beef)) +
    frameOpt('atomicBeef', env.atomicBeef == null ? undefined : lc(env.atomicBeef)) +
    frame('proof') + frame(String(proof.length)) + proofCanon;
  return sha256(Buffer.from(s, 'utf8')).toString('hex');
}

// ---- Outcome composition (§G) — first-match precedence -----------------------------
function classifyOutcome(sig){
  if (sig.evaluationError) return OUTCOME.INDETERMINATE;
  if (sig.malformed)       return OUTCOME.MALFORMED;
  if (sig.failed)          return OUTCOME.FAILED;
  if (sig.policyRejected)  return OUTCOME.POLICY_REJECTED;
  if (sig.cryptoEstablished && !sig.chainLoaded) return OUTCOME.VERIFIED_ISOLATION;
  if (sig.cryptoEstablished && sig.inclusionVerified) return OUTCOME.VERIFIED;
  return OUTCOME.NOT_ESTABLISHED;
}

/**
 * verify(envelope, opts) — independent implementation of the frozen contract.
 * opts.chainHashIndex: optional Map<blockHashDisplay, height> representing a loaded chain.
 * opts.bindRawTx: whether to enforce txid == SHA256d(rawTx) (verifier/chain do; explorer
 *   does not — §C item 1 / scope). Default true.
 */
function verify(envelope, opts){
  opts = opts || {};
  const bindRawTx = opts.bindRawTx !== false;
  const chainHashIndex = opts.chainHashIndex || null;
  const claims = {};
  const advisories = [];
  let identity = null;
  try { identity = evidenceIdentity(envelope || {}); } catch (_) { /* identity is best-effort */ }

  const result = {
    outcome: null, valid: false, claims, advisories,
    chainInclusion: { status: chainHashIndex ? 'pending' : 'unknown', height: null },
    evidenceIdentity: identity,
    claimsNotEstablished: CLAIMS_NOT_ESTABLISHED.map(c => ({ id: c.id, scope: c.scope })),
    diagnostic: null
  };
  const sig = { evaluationError:false, malformed:false, failed:false, policyRejected:false,
                cryptoEstablished:false, chainLoaded: !!chainHashIndex, inclusionVerified:false };

  try {
    if (!envelope || typeof envelope !== 'object') throw new MalformedInput('envelope missing');

    // --- required fields (§B): blockHeader and txid. Absent/empty -> MALFORMED (GAP A).
    // A missing PROOF is NOT malformed and NOT "not-established": it is treated as an empty
    // depth-0 proof, so the Merkle comparison below decides VERIFIED-ISOLATION (single-tx
    // block, txid == root) or FAILED (root mismatch), exactly like the reference.
    if (envelope.blockHeader == null || envelope.blockHeader === '') {
      result.outcome = OUTCOME.MALFORMED;
      result.diagnostic = 'missing/empty blockHeader (required)';
      return result;
    }
    if (envelope.txid == null || envelope.txid === '') {
      result.outcome = OUTCOME.MALFORMED;
      result.diagnostic = 'missing/empty txid (required)';
      return result;
    }

    // --- header (input decode -> MALFORMED; consensus compute -> evalDep) ---
    const hdr = parseHeader(envelope.blockHeader);      // MalformedInput on bad hex/len
    const blockHashDisplay = hashHeaderDisplay(envelope.blockHeader);
    result.blockHash = blockHashDisplay;

    // --- txid <-> rawTx binding (§C item 1) ---
    if (bindRawTx) {
      if (envelope.rawTx == null) { result.outcome = OUTCOME.NOT_ESTABLISHED; result.diagnostic = 'rawTx absent'; return result; }
      let computed;
      try { computed = Buffer.from(sha256d(hexToBytes(envelope.rawTx))).reverse().toString('hex'); }
      catch (e){ throw new MalformedInput('rawTx not decodable'); }
      claims.txidBinding = (lc(computed) === lc(envelope.txid));
      if (!claims.txidBinding) throw new VerificationFailure('txid != SHA256d(rawTx)');
    }

    // --- PoW (consensus dependency) ---
    const pow = evalDep(() => powValid(envelope.blockHeader, hdr.bits));
    claims.pow = pow;
    if (!pow) throw new VerificationFailure('proof-of-work invalid');

    // --- Merkle root binding (§C item 2), proof-source order: bump -> beef -> proof ---
    let computedRoot;
    if (envelope.bump != null) {
      const bump = parseBump(envelope.bump);            // MalformedInput on bad structure
      computedRoot = merkleRootFromBump(bump, envelope.txid); // VerificationFailure if txid absent
    } else if (envelope.beef != null || envelope.atomicBeef != null) {
      // BEEF handling intentionally minimal in this experiment; treated as unsupported here.
      throw new EvaluationError('BEEF path not implemented in headers-node');
    } else {
      computedRoot = merkleRootFromLegacy(envelope.txid, envelope.proof || []); // absent -> depth-0
    }
    claims.merkleRoot = (lc(computedRoot) === lc(hdr.merkleRootDisplay));
    if (!claims.merkleRoot) throw new VerificationFailure('merkle root does not match header');

    // --- header policy (§E): difficulty floor + timestamp sanity ---
    const policy = evalDep(() => headerPolicy(envelope.blockHeader));
    claims.difficultyFloor = policy.valid || policy.reason !== 'below difficulty floor';
    claims.timestamp = policy.valid || (policy.reason || '').indexOf('timestamp') === -1;
    if (!policy.valid) throw new PolicyRejection(policy.reason);

    // all cryptographic + policy claims established at this point
    sig.cryptoEstablished = true;

    // --- chain inclusion (§C item 4) ---
    if (chainHashIndex) {
      const has = evalDep(() => chainHashIndex.has(lc(blockHashDisplay)));
      if (has) {
        result.chainInclusion = { status: 'verified', height: chainHashIndex.get(lc(blockHashDisplay)) };
        sig.inclusionVerified = true;
      } else {
        result.chainInclusion = { status: 'not_in_chain', height: null };
        throw new VerificationFailure('block not in loaded header chain');
      }
    } else {
      result.chainInclusion = { status: 'unknown', height: null };
    }

    // --- advisory: low confirmations (§H) — never changes the outcome ---
    if (typeof envelope.confirmations === 'number' && envelope.confirmations < 6) {
      advisories.push({ id: 'low-confirmations', detail: 'confirmations=' + envelope.confirmations });
    }

    result.outcome = classifyOutcome(sig);
    result.valid = (result.outcome === OUTCOME.VERIFIED || result.outcome === OUTCOME.VERIFIED_ISOLATION);
    return result;

  } catch (e) {
    if (e instanceof EvaluationError)      { sig.evaluationError = true; result.diagnostic = 'evaluation error: ' + e.message; }
    else if (e instanceof MalformedInput)  { sig.malformed = true;       result.diagnostic = 'malformed: ' + e.message; }
    else if (e instanceof PolicyRejection) { sig.policyRejected = true;  result.diagnostic = 'policy: ' + e.message; }
    else if (e instanceof VerificationFailure) { sig.failed = true;      result.diagnostic = 'failed: ' + e.message; }
    else { sig.evaluationError = true;      result.diagnostic = 'unexpected: ' + (e && e.message); } // unknown throw -> INDETERMINATE, fail closed
    result.outcome = classifyOutcome(sig);
    result.valid = false; // any non-verified outcome fails closed
    return result;
  }
}

module.exports = {
  verify, OUTCOME, CHECKPOINT, TOLERANCE,
  evidenceIdentity, classifyOutcome,
  parseHeader, hashHeaderDisplay, targetFromBits, powValid,
  merkleRootFromLegacy, parseBump, merkleRootFromBump, difficultyFloorOk, headerPolicy,
  MalformedInput, EvaluationError, VerificationFailure, PolicyRejection
};
