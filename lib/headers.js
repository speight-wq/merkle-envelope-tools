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
  // Checkpoint anchor. MUST match the anchor of your headers.bin.
  // Verify BOTH hash and nBits independently (e.g. whatsonchain block 939999 / 940000)
  // before trusting high-value transactions — internal PoW validity alone does not prove
  // canonicality (~one BSV block of work can be produced by a resourced attacker).
  // nBits is block 939999's own value (verified via explorer: difficulty 31.886e9,
  // ~2^189); it sets a floor ~2^192 that rejects difficulty-1 and forces ~2^64 to forge.
  const CHECKPOINT = {
    height: 939999,
    hash: '00000000000000000e7aea9b454b4acc945e6ae5883ca7254809e538bb54ef12',
    nBits: 0x18227b71  // real BSV difficulty at block 939999 (difficulty 31.886e9; verify independently)
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

  // Bitcoin/BSV difficulty-1 target (the easiest real difficulty). The floor only has
  // anti-forgery value if it is STRICTER (smaller target) than this; otherwise any
  // grindable difficulty-1 header clears it. This guards against a misconfigured /
  // placeholder checkpoint nBits — e.g. the former 0x1d2a0000 gave a floor ~2^232, looser
  // than difficulty-1 (~2^223), so the floor rejected nothing real. Real BSV nBits near
  // this height is ~0x18xxxxxx (target ~2^189), giving a meaningful floor ~2^192.
  const DIFFICULTY_1_TARGET = targetFromNBits(0x1d00ffff);
  function checkpointFloorStatus() {
    const sane = STATIC_FLOOR_TARGET < DIFFICULTY_1_TARGET;
    return {
      sane: sane,
      reason: sane
        ? 'difficulty floor is stricter than difficulty-1'
        : 'DIFFICULTY FLOOR TOOTHLESS: checkpoint nBits (0x' + CHECKPOINT.nBits.toString(16) +
          ') gives a floor looser than difficulty-1 — grindable low-difficulty headers pass it. ' +
          'Set CHECKPOINT.nBits to the real block ' + CHECKPOINT.height + ' value (~0x18xxxxxx).'
    };
  }
  // Surface the misconfiguration loudly rather than presenting a floor that does nothing.
  try {
    const _cf = checkpointFloorStatus();
    if (!_cf.sane && typeof console !== 'undefined' && console.warn) console.warn('[headers.js] ' + _cf.reason);
  } catch (_e) {}
  
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
    // Raise-only: a loaded chain may make the floor STRICTER (smaller target =
    // harder) but must never make it more permissive than the static checkpoint
    // floor. Otherwise a forged low-difficulty tip could lower the bar for
    // standalone envelope headers (see audit FP-2). Take the harder of the two.
    if (dynamicFloorTarget !== null && dynamicFloorTarget < STATIC_FLOOR_TARGET) {
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

  /**
   * Enforce the per-header difficulty floor over a set of parsed headers.
   * Pure and side-effect free (throws on the first violation) so the policy can be
   * tested with hand-set targets without grinding real PoW. Every header's target must
   * be at or below floorTarget (smaller target = harder). Because chainInclusion()
   * reports "verified" for any header in hashIndex, the floor must hold for EVERY
   * admitted header — not just the tip — otherwise one expensive floor-difficulty tip
   * could be amortised across many cheap forged intermediate headers.
   * @param {Array<{height:number,target:BigInt}>} headers
   * @param {BigInt} floorTarget - STATIC_FLOOR_TARGET (do NOT pass the dynamic floor)
   * @throws if any header.target > floorTarget
   */
  function enforceChainFloor(headers, floorTarget) {
    for (let i = 0; i < headers.length; i++) {
      if (headers[i].target > floorTarget) {
        throw new Error('Header at ' + headers[i].height + ' below difficulty floor ' +
          '(target exceeds checkpoint floor) — possible forged low-difficulty chain');
      }
    }
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

  function verifyHeaderChain(bytes, expectedCheckpoint, options) {
    if (bytes.length < 40) throw new Error('File too small');
    const view = new DataView(bytes.buffer, bytes.byteOffset);
    const anchorHeight = view.getUint32(0, true);
    const anchorHash = global.bytesToHex(bytes.slice(4, 36));
    const headerCount = view.getUint32(36, true);

    // Enforce the checkpoint anchor by default (audit FP-1). Computing
    // checkpointVerified and letting callers proceed anyway meant a headers.bin
    // with a fabricated anchor was accepted, and its blocks reported "chain
    // included". The anchor==embedded-checkpoint check is the ONLY thing pinning
    // a loaded chain to the real network, so it must fail closed here rather than
    // being surfaced as advisory text in three separate call sites.
    // Pass { requireCheckpoint: false } explicitly to opt into the weaker mode.
    const requireCheckpoint = !(options && options.requireCheckpoint === false);
    let checkpointVerified = false;
    if (expectedCheckpoint) {
      if (anchorHeight === expectedCheckpoint.height &&
          anchorHash.toLowerCase() === expectedCheckpoint.hash.toLowerCase()) {
        checkpointVerified = true;
      } else if (requireCheckpoint) {
        throw new Error('Header chain anchor does not match embedded checkpoint ' +
          '(' + expectedCheckpoint.height + '/' + expectedCheckpoint.hash.slice(0, 16) + '…). ' +
          'Refusing a chain not rooted at the trusted checkpoint.');
      }
    } else if (requireCheckpoint) {
      throw new Error('No checkpoint supplied to verifyHeaderChain; cannot anchor chain');
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
      
      // PoW verification (each header against its own nBits)
      const hash = hashHeader(headerHex);
      const target = targetFromNBits(header.nBits);
      if (BigInt('0x' + hash) > target) {
        throw new Error('Invalid PoW at ' + height);
      }

      cumulativeWork += workFromTarget(target);
      headers.push({ height, hash, raw: headerHex, nBits: header.nBits, target });
      hashIndex.set(hash.toLowerCase(), height);
      prevHash = hash;
      tipNBits = header.nBits;
      offset += 80;
    }

    // Difficulty floor — enforced PER HEADER (policy review). chainInclusion() can
    // report "verified" for ANY header in hashIndex, so the floor must hold for every
    // admitted header, not just the tip; this prevents amortising one expensive
    // floor-difficulty tip across many cheap forged intermediate headers. Single
    // enforcement path via enforceChainFloor() (pure, testable). Uses STATIC_FLOOR_TARGET
    // (checkpoint difficulty), never the dynamic/effective floor, so a low-difficulty
    // header cannot lower the bar for the others.
    //
    // Accepted trade-off: a LEGITIMATE chain containing a header genuinely >8x easier
    // than the checkpoint (e.g. a real BSV hashrate crash spanning several max DAA
    // reductions) is rejected. This fails CLOSED — the caller drops to isolation, a
    // supported honest mode, never to a false "verified". Consistent with "false
    // negative over false positive". Full retarget-aware (DAA) difficulty validation
    // would remove the false-negative but is out of scope (not full SPV; see
    // THREAT-MODEL). Do NOT substitute a relative/rolling floor: that reopens the
    // gradual walk-down weakness fixed in snapshot.js. Strength depends on
    // CHECKPOINT.nBits being a real, current difficulty — verify the checkpoint value.
    enforceChainFloor(headers, STATIC_FLOOR_TARGET);

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

  // Maximum Merkle proof depth (32 supports 4 billion tx/block, sufficient for any realistic block)
  const MAX_MERKLE_DEPTH = 32;

  /**
   * Verify a Merkle proof connects a TXID to a Merkle root.
   * 
   * @param {string} txid - Transaction ID in display format (big-endian)
   * @param {Array} proof - Array of {hash, pos} where hash is internal byte order
   * @param {string} merkleRoot - Expected Merkle root in display format
   * @param {Object} options - Optional settings
   * @param {boolean} options.allowWildcard - Allow '*' for self-duplication (default: false)
   * @returns {boolean} True if proof is valid
   */
  function verifyMerkleProof(txid, proof, merkleRoot, options = {}) {
    const allowWildcard = options.allowWildcard === true;
    
    if (!Array.isArray(proof)) throw new Error('Proof must be array');
    if (proof.length > MAX_MERKLE_DEPTH) throw new Error('Merkle proof exceeds maximum depth');
    
    let hash = global.hexToBytes(global.reverseHex(txid));
    
    for (let i = 0; i < proof.length; i++) {
      const step = proof[i];
      
      // Prototype pollution protection
      if (typeof step !== 'object' || step === null) throw new Error('Invalid proof step');
      if (!Object.prototype.hasOwnProperty.call(step, 'hash') ||
          !Object.prototype.hasOwnProperty.call(step, 'pos')) {
        throw new Error('Invalid proof step');
      }
      
      if (step.pos !== 'L' && step.pos !== 'R') throw new Error('Invalid proof position');
      
      let pairHash;
      if (step.hash === '*') {
        // Wildcard represents self-duplication (odd tx count at this level)
        if (!allowWildcard) {
          throw new Error('Wildcard not allowed in untrusted proofs');
        }
        // CVE-2012-2459: Wildcard only valid at leaf level with position R
        // This represents the case where a transaction is duplicated to complete a pair
        if (i !== 0) {
          throw new Error('Wildcard only valid at leaf level (index 0)');
        }
        if (step.pos !== 'R') {
          throw new Error('Wildcard must have position R (self is left, duplicate is right)');
        }
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

  /**
   * Check if a Merkle proof is safe from CVE-2012-2459 attacks.
   * 
   * CVE-2012-2459: A malicious peer could construct a valid-looking Merkle proof
   * for a non-existent transaction by exploiting the duplication of odd nodes.
   * 
   * This function checks for:
   * 1. Adjacent duplicate hashes (same hash at consecutive levels)
   * 2. Wildcards at non-leaf positions
   * 3. Wildcards with incorrect position (must be R)
   * 4. Multiple wildcards (only one self-duplication makes sense)
   * 
   * @param {Array} proof - Merkle proof array
   * @returns {boolean} True if proof structure is safe
   */
  function checkMerkleProofSafe(proof) {
    if (!Array.isArray(proof)) return false;
    
    let wildcardCount = 0;
    let prevHash = null;
    
    for (let i = 0; i < proof.length; i++) {
      const step = proof[i];
      
      // Basic structure check
      if (typeof step !== 'object' || step === null) return false;
      if (!Object.prototype.hasOwnProperty.call(step, 'hash') ||
          !Object.prototype.hasOwnProperty.call(step, 'pos')) {
        return false;
      }
      
      const hash = step.hash;
      const pos = step.pos;
      
      // Check 1: Wildcard constraints
      if (hash === '*') {
        wildcardCount++;
        
        // Only one wildcard allowed
        if (wildcardCount > 1) return false;
        
        // Wildcard only valid at leaf level (index 0)
        if (i !== 0) return false;
        
        // Wildcard must have position R (self on left, duplicate on right)
        if (pos !== 'R') return false;
      }
      
      // Check 2: No adjacent duplicate hashes
      if (hash !== '*' && prevHash !== null && hash === prevHash) {
        return false;
      }
      
      prevHash = hash;
    }
    
    return true;
  }

  /**
   * Three-state chain-inclusion check, shared by verifier.html and explorer.html
   * so the logic is defined and tested in exactly one place.
   * @param {Map|null} hashIndex - hash->height map from verifyHeaderChain, or null
   * @param {string} blockHash - display-order block hash
   * @returns {{status:'verified'|'not_in_chain'|'unknown', verified:boolean, height:number|null, reason:string}}
   */
  function chainInclusion(hashIndex, blockHash) {
    if (!hashIndex) {
      return { status: 'unknown', verified: false, height: null,
        reason: 'no header chain loaded — PoW verified in isolation, not chain inclusion' };
    }
    const bh = String(blockHash).toLowerCase();
    if (hashIndex.has(bh)) {
      const h = hashIndex.get(bh);
      return { status: 'verified', verified: true, height: h,
        reason: 'block found in loaded header chain at height ' + h };
    }
    return { status: 'not_in_chain', verified: false, height: null,
      reason: 'block NOT in loaded header chain — header is not on the chain you hold' };
  }

  /**
   * Permanent scope-boundary anti-claims — properties this verifier DOES NOT ATTEMPT
   * to establish, independent of the evidence or the verdict. These are distinct from
   * evidence-dependent outcomes (e.g. "block not in loaded chain" = evidence failed to
   * establish inclusion). `scope: 'not-attempted'` marks that distinction machine-readably:
   * these say "this tool does not attempt X", never "X is not currently verified".
   * Shared so every consumer states the same boundary in the same words (no drift).
   */
  const SCOPE_ANTICLAIMS = [
    {
      id: 'most-work-chain',
      scope: 'not-attempted',
      label: 'Most-work chain',
      detail: 'A checkpoint-anchored, linked, PoW-valid chain under the configured difficulty ' +
              'policy is verified. This tool does NOT compare cumulative proof-of-work or perform ' +
              'most-work chain selection, so it does not establish that this is the greatest-work chain.'
    },
    {
      id: 'current-spend-status',
      scope: 'not-attempted',
      label: 'Current spend / UTXO status',
      detail: 'Transaction inclusion does NOT establish that an output is currently unspent, ' +
              'spendable, or part of the current UTXO set. This tool does not attempt to determine spend status.'
    }
  ];

  // ---- Evaluation-error boundary (spec §I hardening) -------------------------------
  // A dependency/evaluation failure must classify as INDETERMINATE — never as malformed or
  // cryptographically-invalid evidence. The boundary is SEMANTIC, not the accidental JS
  // error subclass: a consensus/policy dependency is invoked through evalDep(), which tags
  // any throw with a named EvaluationError. Classification then keys on `.name` (realm-safe;
  // works across vm/worker boundaries where `instanceof` does not). Input-decoding and
  // evidence operations are NOT wrapped, so they keep their MALFORMED / FAILED meaning.
  function EvaluationError(cause) {
    this.name = 'EvaluationError';
    this.message = (cause && cause.message) ? cause.message : String(cause);
    this.cause = cause;
  }
  EvaluationError.prototype = Object.create(Error.prototype);
  EvaluationError.prototype.constructor = EvaluationError;
  function evalDep(fn) {
    try { return fn(); }
    catch (e) { throw (e && e.name === 'EvaluationError') ? e : new EvaluationError(e); }
  }
  function isEvaluationError(e) { return !!(e && e.name === 'EvaluationError'); }

  // ---- Canonical semantic outcome vocabulary (spec §F / frozen contract) -----------
  // Shared so verifier/explorer/chain emit ONE outcome vocabulary instead of three legacy
  // encodings (blocker B1). This is a LABEL derived from existing per-claim signals; it does
  // not change any accept/reject decision or any cryptographic computation.
  const OUTCOME = {
    VERIFIED: 'VERIFIED',
    VERIFIED_ISOLATION: 'VERIFIED-ISOLATION',
    FAILED: 'FAILED',
    NOT_ESTABLISHED: 'NOT-ESTABLISHED',
    POLICY_REJECTED: 'POLICY-REJECTED',
    MALFORMED: 'MALFORMED',
    INDETERMINATE: 'INDETERMINATE'
  };

  /**
   * Derive the top-level semantic outcome from per-claim signals, using the FROZEN
   * precedence (spec §G). Pure and total. Detection mechanism separates the top two:
   * `evaluationError` = an exception that was not a declared parse-validation (INDETERMINATE);
   * `malformed` = a controlled parse/structure rejection (MALFORMED).
   * @param {{evaluationError?:boolean, malformed?:boolean, failed?:boolean,
   *          policyRejected?:boolean, cryptoEstablished?:boolean, chainLoaded?:boolean,
   *          inclusionVerified?:boolean}} s
   */
  function classifyOutcome(s) {
    s = s || {};
    if (s.evaluationError) return OUTCOME.INDETERMINATE;                         // 1
    if (s.malformed)       return OUTCOME.MALFORMED;                             // 2
    if (s.failed)          return OUTCOME.FAILED;                               // 3
    if (s.policyRejected)  return OUTCOME.POLICY_REJECTED;                       // 4
    if (s.cryptoEstablished && !s.chainLoaded) return OUTCOME.VERIFIED_ISOLATION;// 5
    if (s.cryptoEstablished && s.inclusionVerified) return OUTCOME.VERIFIED;     // 6
    return OUTCOME.NOT_ESTABLISHED;                                             // fallthrough
  }

  // Exports
  global.CHECKPOINT = CHECKPOINT;
  global.SCOPE_ANTICLAIMS = SCOPE_ANTICLAIMS;
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
  global.enforceChainFloor = enforceChainFloor;
  global.checkpointFloorStatus = checkpointFloorStatus;
  global.chainInclusion = chainInclusion;
  global.OUTCOME = OUTCOME;
  global.classifyOutcome = classifyOutcome;
  global.EvaluationError = EvaluationError;
  global.evalDep = evalDep;
  global.isEvaluationError = isEvaluationError;
})(typeof window !== 'undefined' ? window : global);
