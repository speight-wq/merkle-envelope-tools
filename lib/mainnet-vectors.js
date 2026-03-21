/**
 * mainnet-vectors.js - Real BSV Mainnet Transaction Test Vectors
 * 
 * Contains verified mainnet transactions with:
 * - Full raw transaction hex
 * - Block headers (80 bytes)
 * - Merkle proofs
 * - Block heights
 * 
 * These vectors are deterministic and can be verified offline against
 * the checkpoint and header validation logic.
 * 
 * VERIFICATION SOURCES:
 * - WhatsOnChain API: https://api.whatsonchain.com/v1/bsv/main/
 * - Block headers verified against checkpoint chain
 * - Merkle proofs computed from block data
 */

const MAINNET_TEST_VECTORS = {
  
  // ============================================================
  // VECTOR 1: Genesis block coinbase (block 0)
  // The first ever Bitcoin transaction - protocol constant
  // Identical across BTC, BCH, BSV
  // ============================================================
  vector1: {
    description: "Genesis block coinbase transaction",
    
    txid: "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
    
    blockHeight: 0,
    blockHash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    
    // Genesis block header
    blockHeader: "01000000" +  // version
                 "0000000000000000000000000000000000000000000000000000000000000000" + // prevBlockHash (all zeros)
                 "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" + // merkleRoot
                 "29ab5f49" +  // time - 1231006505
                 "ffff001d" +  // bits - 0x1d00ffff (difficulty 1)
                 "1dac2b7c",   // nonce
    
    // Raw coinbase transaction
    rawTx: "01000000" +  // version
           "01" +  // input count
           "0000000000000000000000000000000000000000000000000000000000000000" + // prevout hash
           "ffffffff" +  // prevout index
           "4d" +  // script length
           "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73" + // coinbase script
           "ffffffff" +  // sequence
           "01" +  // output count
           "00f2052a01000000" +  // value (50 BTC = 5000000000 satoshis)
           "43" +  // script length
           "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac" + // pubkey script
           "00000000",  // locktime
    
    // Merkle proof: empty for single-transaction block
    // In single-tx block, txid == merkleRoot
    merkleProof: [],
    
    merkleRoot: "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
    
    expected: {
      headerPowValid: true,
      merkleProofValid: true,  // Single tx: txid == merkle root
      txidMatchesRaw: true
    }
  },

  // ============================================================
  // VECTOR 2: Block 1 - First mined block after genesis
  // This is also a protocol constant with known values
  // ============================================================
  vector2: {
    description: "Block 1 - First mined block",
    
    txid: "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098",
    
    blockHeight: 1,
    blockHash: "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
    
    // Block 1 header
    blockHeader: "01000000" +  // version
                 "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000" + // prevBlockHash (genesis)
                 "982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e" + // merkleRoot
                 "61bc6649" +  // time - 1231469665
                 "ffff001d" +  // bits - 0x1d00ffff (difficulty 1)
                 "01e36299",   // nonce
    
    // Raw coinbase transaction (correct pubkey for Block 1)
    rawTx: "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000",
    
    // Single-tx block: txid == merkle root
    merkleProof: [],
    
    merkleRoot: "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098",
    
    expected: {
      headerPowValid: true,
      merkleProofValid: true,
      txidMatchesRaw: true
    }
  },

  // ============================================================
  // VECTOR 3: Block 170 - First transaction between two people
  // Famous Satoshi to Hal Finney transaction
  // ============================================================
  vector3: {
    description: "Block 170 - First person-to-person transaction (Satoshi → Hal Finney)",
    
    // Payment transaction TXID (not coinbase)
    txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
    
    blockHeight: 170,
    blockHash: "00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee",
    
    // Block 170 header (verified)
    blockHeader: "01000000" +  // version
                 "55bd840a78798ad0da853f68974f3d183e2bd1db6a842c1feecf222a00000000" + // prevBlockHash
                 "ff104ccb05421ab93e63f8c3ce5c2c2e9dbb37de2764b3a3175c8166562cac7d" + // merkleRoot
                 "51b96a49" +  // time - 1231731025
                 "ffff001d" +  // bits - 0x1d00ffff
                 "283e9e70",   // nonce - 1889418792
    
    // Raw transaction (10 BTC from Satoshi to Hal Finney)
    rawTx: "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000",
    
    // Block 170 has 2 transactions:
    // tx0 (coinbase): b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082
    // tx1 (payment):  f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
    // Sibling hash is coinbase in INTERNAL byte order (little-endian)
    merkleProof: [
      { hash: "82501c1178fa0b222c1f3d474ec726b832013f0a532b44bb620cce8624a5feb1", pos: "L" }
    ],
    
    merkleRoot: "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff",
    
    expected: {
      headerPowValid: true,
      merkleProofValid: true,
      txidMatchesRaw: true
    }
  }
};

// ============================================================
// INVALID TEST VECTORS - Must all FAIL verification
// ============================================================

const INVALID_TEST_VECTORS = {
  
  // Modified Merkle proof - should fail
  invalidMerkleProof: {
    description: "Valid header but corrupted Merkle branch",
    txid: MAINNET_TEST_VECTORS.vector3.txid,
    blockHeader: MAINNET_TEST_VECTORS.vector3.blockHeader,
    merkleRoot: MAINNET_TEST_VECTORS.vector3.merkleRoot,
    // One byte changed in branch hash (first byte 82 -> 00)
    merkleProof: [
      { hash: "00501c1178fa0b222c1f3d474ec726b832013f0a532b44bb620cce8624a5feb1", pos: "L" }
    ],
    expected: {
      merkleProofValid: false
    }
  },
  
  // Invalid PoW - header hash doesn't meet difficulty
  invalidPoW: {
    description: "Header with invalid proof-of-work (nonce=0)",
    txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    // Genesis header with nonce zeroed out - won't meet difficulty
    blockHeader: "01000000" +  // version
                 "0000000000000000000000000000000000000000000000000000000000000000" + 
                 "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" + 
                 "29ab5f49" +  
                 "ffff001d" +  // difficulty 1
                 "00000000",   // nonce = 0 (invalid, won't meet target)
    merkleProof: [],
    expected: {
      headerPowValid: false
    }
  },
  
  // Difficulty too low (below floor)
  difficultyTooLow: {
    description: "Header with difficulty below checkpoint floor",
    txid: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    // Header with very low difficulty (nBits = 0x207fffff is essentially difficulty 1/4)
    blockHeader: "01000000" +
                 "0000000000000000000000000000000000000000000000000000000000000000" +
                 "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" +
                 "29ab5f49" +
                 "ffff7f20" +  // 0x207fffff - way too easy
                 "00000000",
    merkleProof: [],
    expected: {
      difficultyFloorValid: false
    }
  },
  
  // TXID doesn't match raw transaction
  txidMismatch: {
    description: "TXID does not match hash of raw transaction",
    txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // Wrong TXID
    rawTx: MAINNET_TEST_VECTORS.vector1.rawTx,  // Genesis coinbase (different tx)
    expected: {
      txidMatchesRaw: false
    }
  },
  
  // CVE-2012-2459: Duplicate adjacent nodes in Merkle proof
  duplicateNodes: {
    description: "Merkle proof with duplicate adjacent nodes (CVE-2012-2459)",
    txid: MAINNET_TEST_VECTORS.vector3.txid,
    blockHeader: MAINNET_TEST_VECTORS.vector3.blockHeader,
    merkleProof: [
      { hash: "169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f4", pos: "R" },
      { hash: "169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f4", pos: "R" } // Duplicate!
    ],
    expected: {
      merkleProofSafe: false
    }
  },
  
  // CVE-2012-2459: Wildcard at non-leaf position
  wildcardNonLeaf: {
    description: "Wildcard '*' at non-leaf position (CVE-2012-2459)",
    txid: MAINNET_TEST_VECTORS.vector3.txid,
    merkleProof: [
      { hash: "169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f4", pos: "R" },
      { hash: "*", pos: "R" }  // Wildcard at index 1, not leaf
    ],
    expected: {
      merkleProofSafe: false
    }
  },
  
  // CVE-2012-2459: Wildcard with wrong position
  wildcardWrongPos: {
    description: "Wildcard '*' with position L instead of R (CVE-2012-2459)",
    txid: MAINNET_TEST_VECTORS.vector3.txid,
    merkleProof: [
      { hash: "*", pos: "L" }  // Wildcard must be R (self left, duplicate right)
    ],
    expected: {
      merkleProofSafe: false
    }
  },
  
  // CVE-2012-2459: Multiple wildcards
  multipleWildcards: {
    description: "Multiple wildcards in proof (CVE-2012-2459)",
    txid: MAINNET_TEST_VECTORS.vector3.txid,
    merkleProof: [
      { hash: "*", pos: "R" },
      { hash: "*", pos: "R" }  // Second wildcard - invalid
    ],
    expected: {
      merkleProofSafe: false
    }
  },
  
  // Prototype pollution attempt
  prototypePollution: {
    description: "Proof step missing own properties (prototype pollution)",
    txid: MAINNET_TEST_VECTORS.vector3.txid,
    // This simulates an object that inherits hash/pos from prototype
    // In real attack: Object.prototype.hash = "..."; Object.prototype.pos = "R";
    // Then pass [{}] as proof - empty object inherits polluted properties
    merkleProof: "SPECIAL_TEST", // Marker for test code to construct attack
    expected: {
      merkleProofSafe: false
    }
  }
};

// ============================================================
// CHECKPOINT VERIFICATION DATA
// ============================================================

const CHECKPOINT_VERIFICATION = {
  // Block 935000 - our checkpoint
  checkpoint: {
    height: 935000,
    hash: "000000000000000014dd029be96be37223e04f66f379dc4eed0f071a73c1f7aa",
    nBits: 0x1d2a0000
  },
  
  // Block headers AFTER checkpoint (for chain verification)
  // These would need to link from checkpoint
  postCheckpointHeaders: [
    // Would include headers 935001, 935002, etc.
  ]
};

// Export for use in tests
if (typeof window !== 'undefined') {
  window.MAINNET_TEST_VECTORS = MAINNET_TEST_VECTORS;
  window.INVALID_TEST_VECTORS = INVALID_TEST_VECTORS;
  window.CHECKPOINT_VERIFICATION = CHECKPOINT_VERIFICATION;
}

if (typeof module !== 'undefined') {
  module.exports = { MAINNET_TEST_VECTORS, INVALID_TEST_VECTORS, CHECKPOINT_VERIFICATION };
}
