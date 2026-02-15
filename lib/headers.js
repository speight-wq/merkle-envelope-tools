/**
 * headers.js - Block header verification
 * Merkle Envelope Tools
 * Depends on: crypto.js, encoding.js
 */
(function(global) {
  'use strict';

  const CHECKPOINT = {
    height: 880000,
    hash: '0000000000000000067ef53e9c4bf1297d0860a36b81b0e03ad0be6fb719788d'
  };

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

    // If expectedCheckpoint provided and matches anchor, that's good
    // But we don't require it - we verify chain is internally consistent
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

    for (let i = 0; i < headerCount; i++) {
      const height = anchorHeight + 1 + i;
      const headerHex = global.bytesToHex(bytes.slice(offset, offset + 80));
      const header = parseHeader(headerHex);
      if (header.prevBlock.toLowerCase() !== prevHash.toLowerCase()) throw new Error('Chain break at ' + height);
      const hash = hashHeader(headerHex);
      const target = targetFromNBits(header.nBits);
      if (BigInt('0x' + hash) > target) throw new Error('Invalid PoW at ' + height);
      cumulativeWork += workFromTarget(target);
      headers.push({ height, hash, raw: headerHex });
      hashIndex.set(hash.toLowerCase(), height);
      prevHash = hash;
      offset += 80;
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

  function verifyMerkleProof(txid, proof, merkleRoot) {
    let hash = global.hexToBytes(global.reverseHex(txid));
    for (const step of proof) {
      // TSC format uses '*' to indicate duplicate (hash with itself)
      const pairHash = (step.hash === '*') ? hash : global.hexToBytes(step.hash);
      const concat = new Uint8Array(64);
      if (step.pos === 'L') {
        concat.set(pairHash, 0); concat.set(hash, 32);
      } else {
        concat.set(hash, 0); concat.set(pairHash, 32);
      }
      hash = global.hash256(global.bytesToHex(concat));
    }
    return global.bytesToHex(hash.reverse()).toLowerCase() === merkleRoot.toLowerCase();
  }

  function checkMerkleProofSafe(proof) {
    for (let i = 1; i < proof.length; i++) {
      if (proof[i].hash === proof[i - 1].hash) return false;
    }
    return true;
  }

  global.CHECKPOINT = CHECKPOINT;
  global.parseHeader = parseHeader;
  global.parseHeaderBytes = parseHeaderBytes;
  global.targetFromNBits = targetFromNBits;
  global.workFromTarget = workFromTarget;
  global.hashHeader = hashHeader;
  global.verifyPoW = verifyPoW;
  global.verifyHeaderChain = verifyHeaderChain;
  global.verifyMerkleProof = verifyMerkleProof;
  global.checkMerkleProofSafe = checkMerkleProofSafe;
})(typeof window !== 'undefined' ? window : global);
