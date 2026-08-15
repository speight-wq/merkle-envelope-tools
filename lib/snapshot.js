/**
 * snapshot.js - Signed Header Snapshot Support
 * Merkle Envelope Tools
 * 
 * Signature authenticates DISTRIBUTION only, not consensus.
 * PoW and cumulative work remain the sole validity criteria (whitepaper-aligned).
 * Depends on: crypto.js, encoding.js, secp256k1.js, headers.js
 */
(function(global) {
  'use strict';

  /**
   * Snapshot JSON Schema:
   * {
   *   version: 1,
   *   startHeight: number,
   *   endHeight: number,
   *   anchorHash: string,        // Hash of block at startHeight (32 bytes hex)
   *   headers: string,           // Concatenated 80-byte headers as hex
   *   cumulativeWork: string,    // BigInt as hex string (no 0x prefix)
   *   timestamp: number,         // Unix seconds when snapshot was created
   *   signerPubKey: string,      // 33-byte compressed pubkey as hex
   *   signature: string          // DER signature as hex
   * }
   */

  // Snapshot timestamp bounds
  const MAX_SNAPSHOT_FUTURE_SECONDS = 7200;  // 2 hours (matches Bitcoin block timestamp)
  const MAX_SNAPSHOT_AGE_SECONDS = 86400 * 30; // 30 days (stale snapshot warning threshold)

  /**
   * Build canonical message for signing/verification.
   * Deterministic binary serialization - NO JSON stringification.
   * 
   * Format: hash256(startHeight || endHeight || anchorHash || headers || cumulativeWork || timestamp)
   *   - Heights: 8-byte big-endian (unambiguous, fixed-width)
   *   - anchorHash: 32-byte binary (natural byte order, not reversed)
   *   - Headers: raw 80-byte binary (concatenated)
   *   - cumulativeWork: 32-byte big-endian (fixed-width, no length ambiguity)
   *   - timestamp: 8-byte big-endian
   * 
   * Security: All fields are fixed-width or self-delimiting (headers count derived from
   * heights). No length prefixes needed. hash256 (double SHA-256) is collision-resistant
   * and consistent with Bitcoin's hashing convention.
   * 
   * @param {Object} snapshot - Snapshot object (signature field ignored)
   * @returns {Uint8Array} - 32-byte hash
   */
  function buildCanonicalMessage(snapshot) {
    const headersBytes = global.hexToBytes(snapshot.headers);
    const workBigInt = BigInt('0x' + snapshot.cumulativeWork);
    const anchorBytes = snapshot.anchorHash ? global.hexToBytes(snapshot.anchorHash) : new Uint8Array(32);
    
    // Total: 8 + 8 + 32 + headers + 32 + 8 = 88 + headers.length
    const msg = new Uint8Array(88 + headersBytes.length);
    const view = new DataView(msg.buffer);
    
    let offset = 0;
    
    // Heights as 8-byte big-endian (supports heights > 2^32, unambiguous encoding)
    view.setBigUint64(offset, BigInt(snapshot.startHeight), false);
    offset += 8;
    view.setBigUint64(offset, BigInt(snapshot.endHeight), false);
    offset += 8;
    
    // Anchor hash as 32-byte binary (commits to chain position)
    msg.set(anchorBytes, offset);
    offset += 32;
    
    // Headers as raw binary (length implied by endHeight - startHeight)
    msg.set(headersBytes, offset);
    offset += headersBytes.length;
    
    // cumulativeWork as 32-byte big-endian (fixed-width prevents length confusion)
    const workBytes = new Uint8Array(32);
    let w = workBigInt;
    for (let i = 31; i >= 0; i--) {
      workBytes[i] = Number(w & 0xffn);
      w >>= 8n;
    }
    msg.set(workBytes, offset);
    offset += 32;
    
    // Timestamp as 8-byte big-endian
    view.setBigUint64(offset, BigInt(snapshot.timestamp), false);
    
    // Double SHA-256: collision-resistant, consistent with Bitcoin convention
    // Input is raw bytes, not hex string, ensuring deterministic output
    return global.hash256(global.bytesToHex(msg));
  }

  /**
   * Verify a signed header snapshot.
   * 
   * Security properties verified:
   * 1. Schema validation (version, types, ranges)
   * 2. Timestamp bounds (not future, not excessively stale)
   * 3. Signer whitelist (distribution trust)
   * 4. Anchor hash matches first header's prevBlock (chain position)
   * 5. Header linkage (each prevBlock = hash of previous)
   * 6. PoW verification (hash <= target for each header)
   * 7. Difficulty floor (rejects trivially forged low-difficulty headers)
   * 8. Cumulative work recomputed locally (never trusted from snapshot)
   * 9. Declared work == computed work (fail closed on mismatch)
   * 10. Signature over canonical hash (authenticates distribution source)
   * 
   * @param {Object} snapshot - Signed snapshot object
   * @param {string[]} trustedPubKeys - Array of trusted 33-byte pubkeys (hex)
   * @param {Object} [options] - Optional verification parameters
   * @param {string} [options.expectedAnchorHash] - Expected anchor hash for checkpoint binding
   * @returns {{ valid: boolean, reason?: string, warnings?: string[], result?: Object }}
   */
  function verifySnapshot(snapshot, trustedPubKeys, options = {}) {
    const warnings = [];
    
    // ==========================================
    // 1. Schema validation
    // ==========================================
    if (snapshot.version !== 1) {
      return { valid: false, reason: 'Unknown snapshot version' };
    }
    if (typeof snapshot.startHeight !== 'number' || !Number.isInteger(snapshot.startHeight) ||
        typeof snapshot.endHeight !== 'number' || !Number.isInteger(snapshot.endHeight) ||
        snapshot.endHeight <= snapshot.startHeight ||
        snapshot.startHeight < 0) {
      return { valid: false, reason: 'Invalid height range' };
    }
    if (typeof snapshot.timestamp !== 'number' || !Number.isInteger(snapshot.timestamp)) {
      return { valid: false, reason: 'Invalid timestamp' };
    }
    if (typeof snapshot.headers !== 'string' || !global.isValidHex(snapshot.headers)) {
      return { valid: false, reason: 'Invalid headers format' };
    }
    if (typeof snapshot.cumulativeWork !== 'string' || !/^[0-9a-fA-F]+$/.test(snapshot.cumulativeWork)) {
      return { valid: false, reason: 'Invalid cumulativeWork format' };
    }
    if (typeof snapshot.signerPubKey !== 'string' || snapshot.signerPubKey.length !== 66) {
      return { valid: false, reason: 'Invalid signerPubKey format' };
    }
    if (typeof snapshot.signature !== 'string' || !global.isValidHex(snapshot.signature)) {
      return { valid: false, reason: 'Invalid signature format' };
    }
    
    const expectedHeaderCount = snapshot.endHeight - snapshot.startHeight;
    if (snapshot.headers.length !== expectedHeaderCount * 160) {
      return { valid: false, reason: `Header count mismatch: expected ${expectedHeaderCount}, got ${snapshot.headers.length / 160}` };
    }
    
    // ==========================================
    // 2. Timestamp validation
    // ==========================================
    const now = Math.floor(Date.now() / 1000);
    
    // Reject snapshots from the future (clock skew tolerance: 2 hours)
    if (snapshot.timestamp > now + MAX_SNAPSHOT_FUTURE_SECONDS) {
      return { valid: false, reason: 'Snapshot timestamp is in the future' };
    }
    
    // Warn about stale snapshots (but don't reject - user may intentionally use old data)
    if (snapshot.timestamp < now - MAX_SNAPSHOT_AGE_SECONDS) {
      warnings.push(`Snapshot is ${Math.floor((now - snapshot.timestamp) / 86400)} days old`);
    }
    
    // ==========================================
    // 3. Signer whitelist (before expensive crypto)
    // ==========================================
    const signerNormalized = snapshot.signerPubKey.toLowerCase();
    const trusted = trustedPubKeys.some(pk => pk.toLowerCase() === signerNormalized);
    if (!trusted) {
      return { valid: false, reason: 'Signer not in trusted set' };
    }
    
    // ==========================================
    // 4. Anchor hash validation
    // ==========================================
    // The anchor hash commits to a specific chain position. Without it, an attacker
    // could provide valid headers that chain internally but start from a fake anchor.
    const hasAnchorHash = snapshot.anchorHash && snapshot.anchorHash.length === 64;
    
    if (options.expectedAnchorHash) {
      if (!hasAnchorHash) {
        return { valid: false, reason: 'Snapshot missing anchorHash but expectedAnchorHash provided' };
      }
      if (snapshot.anchorHash.toLowerCase() !== options.expectedAnchorHash.toLowerCase()) {
        return { valid: false, reason: 'Anchor hash does not match expected checkpoint' };
      }
    }
    
    // ==========================================
    // 5-8. Header chain verification with difficulty floor
    // ==========================================
    const headersHex = snapshot.headers;
    let prevHash = hasAnchorHash ? snapshot.anchorHash : null;
    let computedWork = 0n;
    let tipNBits = null;
    
    // Tip-only difficulty floor (consistent with headers.js finding-D fix): the floor
    // is fixed at the static checkpoint floor and enforced on the snapshot TIP. The
    // previous code walked the floor DOWN to (target * 8) after each header, which let a
    // signed snapshot ramp difficulty down ≤8x per step indefinitely — a low-difficulty
    // synthetic tail. Enforcing the tip against a fixed floor blocks that while still
    // permitting a genuine intermediate difficulty drop.
    const staticFloorTarget = (global.STATIC_FLOOR_TARGET !== undefined)
      ? global.STATIC_FLOOR_TARGET : global.getEffectiveFloor().target;
    let lastTarget = null;
    
    for (let i = 0; i < expectedHeaderCount; i++) {
      const height = snapshot.startHeight + 1 + i;
      const headerHex = headersHex.slice(i * 160, (i + 1) * 160);
      const header = global.parseHeader(headerHex);
      const hash = global.hashHeader(headerHex);
      const target = global.targetFromNBits(header.nBits);
      
      // 5. Chain linkage verification
      // First header must chain from anchor (if provided)
      // Subsequent headers must chain from previous
      if (prevHash !== null && header.prevBlock.toLowerCase() !== prevHash.toLowerCase()) {
        return { valid: false, reason: `Chain break at height ${height} (offset ${i})` };
      }
      
      // 6. PoW verification (hash must be <= target)
      if (BigInt('0x' + hash) > target) {
        return { valid: false, reason: `Invalid PoW at height ${height}` };
      }
      
      // 7. Difficulty floor is enforced on the TIP after the loop (raise-only,
      // fixed at the static checkpoint floor) — see note above.

      // 8. Timestamp sanity (individual headers)
      if (header.timestamp < 1231006505) { // Genesis timestamp
        return { valid: false, reason: `Header at height ${height} has pre-genesis timestamp` };
      }
      if (header.timestamp > now + 7200) {
        return { valid: false, reason: `Header at height ${height} has future timestamp` };
      }
      
      // Accumulate work (whitepaper: sum of work is consensus metric)
      computedWork += global.workFromTarget(target);
      prevHash = hash;
      tipNBits = header.nBits;
      lastTarget = target;
    }

    // 7 (tip). Difficulty floor on the snapshot tip — blocks a low-difficulty synthetic
    // tail without falsely rejecting a genuine intermediate difficulty drop.
    if (lastTarget !== null && lastTarget > staticFloorTarget) {
      return { valid: false, reason: 'Snapshot tip below difficulty floor (possible synthetic chain)' };
    }
    
    // ==========================================
    // 9. Cumulative work verification (fail closed)
    // ==========================================
    const declaredWork = BigInt('0x' + snapshot.cumulativeWork);
    if (computedWork !== declaredWork) {
      return { valid: false, reason: 'Cumulative work mismatch (possible tampering)' };
    }
    
    // ==========================================
    // 10. Signature verification
    // ==========================================
    // SECP256K1.verify takes HEX strings (messageHashHex, DER signatureHex, pubKeyHex)
    // and validates internally (returns false on malformed input). Previously this called
    // a lowercase `global.secp256k1` (undefined -> crash) and passed Uint8Arrays.
    const msgHashHex = global.bytesToHex(buildCanonicalMessage(snapshot));
    if (!global.SECP256K1 || typeof global.SECP256K1.verify !== 'function') {
      return { valid: false, reason: 'secp256k1 library not loaded' };
    }
    if (!global.SECP256K1.verify(msgHashHex, snapshot.signature, snapshot.signerPubKey)) {
      return { valid: false, reason: 'Signature verification failed' };
    }
    
    // ==========================================
    // All checks passed
    // ==========================================
    return {
      valid: true,
      warnings: warnings.length > 0 ? warnings : undefined,
      result: {
        startHeight: snapshot.startHeight,
        endHeight: snapshot.endHeight,
        headerCount: expectedHeaderCount,
        cumulativeWork: computedWork,
        tipHash: prevHash,
        tipNBits: tipNBits,
        anchorHash: snapshot.anchorHash || null,
        signer: snapshot.signerPubKey,
        timestamp: snapshot.timestamp,
        age: now - snapshot.timestamp
      }
    };
  }

  /**
   * Create a signed snapshot (for snapshot creators).
   * 
   * @param {number} startHeight - Anchor height (first header is startHeight + 1)
   * @param {string} anchorHash - Hash of block at startHeight (for chain binding)
   * @param {string} headersHex - Concatenated 80-byte headers
   * @param {string} privateKeyHex - 32-byte private key as 64 hex chars
   * @returns {Object} - Signed snapshot object
   */
  function createSnapshot(startHeight, anchorHash, headersHex, privateKeyHex) {
    const headerCount = headersHex.length / 160;
    const endHeight = startHeight + headerCount;
    
    // Compute cumulative work
    let cumulativeWork = 0n;
    for (let i = 0; i < headerCount; i++) {
      const headerHex = headersHex.slice(i * 160, (i + 1) * 160);
      const header = global.parseHeader(headerHex);
      cumulativeWork += global.workFromTarget(global.targetFromNBits(header.nBits));
    }
    
    const snapshot = {
      version: 1,
      startHeight,
      endHeight,
      anchorHash: anchorHash,
      headers: headersHex,
      cumulativeWork: cumulativeWork.toString(16).padStart(64, '0'),
      timestamp: Math.floor(Date.now() / 1000),
      // getPublicKey returns a hex string already — do NOT wrap in bytesToHex.
      signerPubKey: global.SECP256K1.getPublicKey(privateKeyHex, true),
      signature: '' // Placeholder
    };

    // Sign canonical message. SECP256K1.sign takes hex, returns {r,s}; serialize to DER hex.
    const msgHashHex = global.bytesToHex(buildCanonicalMessage(snapshot));
    const sig = global.SECP256K1.sign(msgHashHex, privateKeyHex);
    snapshot.signature = global.SECP256K1.signatureToDER(sig.r, sig.s);

    return snapshot;
  }

  // Exports
  global.buildCanonicalMessage = buildCanonicalMessage;
  global.verifySnapshot = verifySnapshot;
  global.createSnapshot = createSnapshot;
  global.MAX_SNAPSHOT_FUTURE_SECONDS = MAX_SNAPSHOT_FUTURE_SECONDS;
  global.MAX_SNAPSHOT_AGE_SECONDS = MAX_SNAPSHOT_AGE_SECONDS;

})(typeof window !== 'undefined' ? window : global);
