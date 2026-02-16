/**
 * headers.js - Block header verification
 * Merkle Envelope Tools
 * Depends on: crypto.js, encoding.js
 */
(function(global) {
  'use strict';

  // ==========================================
  // Checkpoint Configuration
  // ==========================================
  // Updated to recent block for tighter difficulty floor.
  // Verify hash via: whatsonchain.com/block-height/935000
  const CHECKPOINT = {
    height: 935000,
    hash: '00000000000000000482b4dbe828e0ce479e71e5986eb14374757a7e4eb30e02',
    nBits: 0x1804596e  // ~73x easier than block 880000
  };

  // ==========================================
  // Difficulty Floor System
  // ==========================================
  // 
  // Two-tier floor:
  // 1. Static floor: Based on checkpoint nBits with 8x tolerance
  // 2. Dynamic floor: When header chain loaded, uses chain tip's nBits
  //
  // The 8x tolerance allows ~3 consecutive max difficulty reductions
  // (BSV: 50% per period = 0.5^3 = 12.5% = 1/8)
  //
  // This blocks trivially forged headers (difficulty-1) while accepting
  // legitimate blocks during normal hashrate variance.
  
  const DIFFICULTY_TOLERANCE = 8n;
  
  // Static floor from checkpoint (used when no header chain loaded)
  const STATIC_FLOOR_TARGET = targetFromNBits(CHECKPOINT.nBits) * DIFFICULTY_TOLERANCE;
  
  // Dynamic floor state (updated when header chain is loaded)
  let dynamicFloorTarget = null;
  let dynamicFloorSource = null;

  /**
   * Set dynamic difficulty floor from loaded header chain tip.
   * Called by verifyHeaderChain after successful verification.
   * @param {number} tipNBits - nBits from chain tip
   * @param {number} tipHeight - Height of chain tip
   */
  function setDynamicFloor(tipNBits, tipHeight) {
    dynamicFloorTarget = targetFromNBits(tipNBits) * DIFFICULTY_TOLERANCE;
    dynamicFloorSource = { height: tipHeight, nBits: tipNBits };
  }

  /**
   * Clear dynamic floor (revert to static checkpoint floor).
   */
  function clearDynamicFloor() {
    dynamicFloorTarget = null;
    dynamicFloorSource = null;
  }

  /**
   * Get current effective floor target.
   * Uses dynamic floor if set, otherwise static checkpoint floor.
   * @returns {{ target: BigInt, source: string }}
   */
  function getEffectiveFloor() {
    if (dynamicFloorTarget !== null) {
      return {
        target: dynamicFloorTarget,
        source: `chain tip ${dynamicFloorSource.height}`
      };
    }
    return {
      target: STATIC_FLOOR_TARGET,
      source: `checkpoint ${CHECKPOINT.height}`
    };
  }

  // Timestamp bounds
  const GENESIS_TIMESTAMP = 1231006505n;
  const MAX_FUTURE_SECONDS = 7200n;

  // ==========================================
  // Difficulty Floor Validation
  // ==========================================
  
  /**
   * Validate header meets minimum difficulty floor.
   * @param {Object} header - Parsed header with nBits, timestamp
   * @param {number} height - Block height (optional, for better error messages)
   * @returns {{ valid: boolean, reason?: string }}
   */
  function validateDifficultyFloor(header, height) {
    const target = targetFromNBits(header.nBits);
    const floor = getEffectiveFloor();
    
    // Header target must not exceed floor (lower target = harder = OK)
    if (target > floor.target) {
      return {
        valid: false,
        reason: `Difficulty too low${height ? ' for height ' + height : ''}. ` +
                `Floor from ${floor.source}.`
      };
    }
    
    // Timestamp sanity checks
    if (BigInt(header.timestamp) < GENESIS_TIMESTAMP) {
      return { valid: false, reason: 'Timestamp before genesis block' };
    }
    
    const now = BigInt(Math.floor(Date.now() / 1000));
    if (BigInt(header.timestamp) > now + MAX_FUTURE_SECONDS) {
      return { valid: false, reason: 'Timestamp too far in future' };
    }
    
    return { valid: true };
  }

  /**
   * Validate standalone header difficulty (for envelope verification).
   * @param {string} headerHex - 80-byte header as hex
   * @returns {{ valid: boolean, reason?: string }}
   */
  function validateHeaderDifficulty(headerHex) {
    const header = parseHeader(headerHex);
    return validateDifficultyFloor(header, null);
  }

  // ==========================================
  // Header Parsing
  // ==========================================

  function parseHeader(headerHex) {
    const bytes = global.hexToBytes(headerHex);
    if (bytes.length !== 80) throw new Error('Header must be 80 bytes');
    const view = new DataView(bytes.buffer);
    return {
      version: view.getUint32(0, true),
      prevBlock: global.bytesToHex(bytes.slice(4, 36).reverse()),
      merkleRoot: global.bytesToHex(bytes.slice(36, 68).reverse()),
      timestamp: view.getUint32(68, true),
      nBits: view.getUint32(72, true),
      nonce: view.getUint32(76, true)
    };
  }

  function parseHeaderBytes(bytes, offset) {
    if (bytes.length < offset + 80) throw new Error('Insufficient bytes');
    const headerBytes = bytes.slice(offset, offset + 80);
    const view = new DataView(headerBytes.buffer, headerBytes.byteOffset, 80);
    return {
      version: view.getUint32(0, true),
      prevBlock: global.bytesToHex(headerBytes.slice(4, 36).reverse()),
      merkleRoot: global.bytesToHex(headerBytes.slice(36, 68).reverse()),
      timestamp: view.getUint32(68, true),
      nBits: view.getUint32(72, true),
      nonce: view.getUint32(76, true),
      raw: global.bytesToHex(headerBytes)
    };
  }

  function targetFromNBits(nBits) {
    const exp = (nBits >>> 24) & 0xff;
    const mant = nBits & 0x7fffff;
    if (exp <= 3) return BigInt(mant >>> (8 * (3 - exp)));
    return BigInt(mant) << BigInt(8 * (exp - 3));
  }

  function workFromTarget(target) {
    return (1n << 256n) / (target + 1n);
  }

  function hashHeader(headerHex) {
    return global.reverseHex(global.bytesToHex(global.hash256(headerHex)));
  }

  function verifyPoW(headerHex) {
    const header = parseHeader(headerHex);
    const hash = hashHeader(headerHex);
    const target = targetFromNBits(header.nBits);
    return BigInt('0x' + hash) <= target;
  }

  function verifyHeaderChain(bytes, expectedCheckpoint) {
    if (bytes.length < 40) throw new Error('File too small');
    const view = new DataView(bytes.buffer, bytes.byteOffset);
    const anchorHeight = view.getUint32(0, true);
    const anchorHash = global.bytesToHex(bytes.slice(4, 36));
    const headerCount = view.getUint32(36, true);

    let checkpointVerified = false;
    if (expectedCheckpoint) {
      if (anchorHeight === expectedCheckpoint.height && 
          anchorHash.toLowerCase() === expectedCheckpoint.hash.toLowerCase()) {
        checkpointVerified = true;
      }
    }

    if (bytes.length < 40 + headerCount * 80) throw new Error('File truncated');

    const headers = [], hashIndex = new Map();
    let prevHash = anchorHash, cumulativeWork = 0n, offset = 40;
    let tipNBits = null;

    for (let i = 0; i < headerCount; i++) {
      const height = anchorHeight + 1 + i;
      const headerHex = global.bytesToHex(bytes.slice(offset, offset + 80));
      const header = parseHeader(headerHex);
      
      // Chain linkage
      if (header.prevBlock.toLowerCase() !== prevHash.toLowerCase()) {
        throw new Error('Chain break at ' + height);
      }
      
      // PoW verification
      const hash = hashHeader(headerHex);
      const target = targetFromNBits(header.nBits);
      if (BigInt('0x' + hash) > target) {
        throw new Error('Invalid PoW at ' + height);
      }
      
      cumulativeWork += workFromTarget(target);
      headers.push({ height, hash, raw: headerHex, nBits: header.nBits });
      hashIndex.set(hash.toLowerCase(), height);
      prevHash = hash;
      tipNBits = header.nBits;
      offset += 80;
    }

    // Set dynamic floor from chain tip
    if (headers.length > 0) {
      const tip = headers[headers.length - 1];
      setDynamicFloor(tip.nBits, tip.height);
    }

    return {
      anchor: { height: anchorHeight, hash: anchorHash },
      checkpointVerified,
      headers, hashIndex,
      tipHeight: headers.length > 0 ? headers[headers.length - 1].height : anchorHeight,
      tipHash: headers.length > 0 ? headers[headers.length - 1].hash : anchorHash,
      cumulativeWork
    };
  }

  // Maximum Merkle proof depth
  const MAX_MERKLE_DEPTH = 64;

  function verifyMerkleProof(txid, proof, merkleRoot) {
    if (!Array.isArray(proof)) throw new Error('Proof must be array');
    if (proof.length > MAX_MERKLE_DEPTH) throw new Error('Merkle proof exceeds maximum depth');
    
    let hash = global.hexToBytes(global.reverseHex(txid));
    for (const step of proof) {
      if (typeof step !== 'object' || step === null) throw new Error('Invalid proof step');
      if (step.pos !== 'L' && step.pos !== 'R') throw new Error('Invalid proof position');
      
      let pairHash;
      if (step.hash === '*') {
        pairHash = hash;
      } else {
        if (!global.isValidHex(step.hash) || step.hash.length !== 64) {
          throw new Error('Invalid proof hash');
        }
        pairHash = global.hexToBytes(step.hash);
      }
      
      const concat = new Uint8Array(64);
      if (step.pos === 'L') {
        concat.set(pairHash, 0); concat.set(hash, 32);
      } else {
        concat.set(hash, 0); concat.set(pairHash, 32);
      }
      hash = global.hash256(global.bytesToHex(concat));
    }
    return global.constantTimeEqual(
      global.bytesToHex(hash.reverse()).toLowerCase(),
      merkleRoot.toLowerCase()
    );
  }

  function checkMerkleProofSafe(proof) {
    for (let i = 1; i < proof.length; i++) {
      if (proof[i].hash === proof[i - 1].hash) return false;
    }
    return true;
  }

  // Exports
  global.CHECKPOINT = CHECKPOINT;
  global.STATIC_FLOOR_TARGET = STATIC_FLOOR_TARGET;
  global.parseHeader = parseHeader;
  global.parseHeaderBytes = parseHeaderBytes;
  global.targetFromNBits = targetFromNBits;
  global.workFromTarget = workFromTarget;
  global.hashHeader = hashHeader;
  global.verifyPoW = verifyPoW;
  global.verifyHeaderChain = verifyHeaderChain;
  global.verifyMerkleProof = verifyMerkleProof;
  global.checkMerkleProofSafe = checkMerkleProofSafe;
  global.validateDifficultyFloor = validateDifficultyFloor;
  global.validateHeaderDifficulty = validateHeaderDifficulty;
  global.setDynamicFloor = setDynamicFloor;
  global.clearDynamicFloor = clearDynamicFloor;
  global.getEffectiveFloor = getEffectiveFloor;
})(typeof window !== 'undefined' ? window : global);
