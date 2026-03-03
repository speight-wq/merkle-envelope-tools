#!/usr/bin/env python3
"""
verify_vectors.py - Independent verification of BSV mainnet test vectors

This script verifies all test vectors from lib/mainnet-vectors.js using
only Python standard library (hashlib). No external dependencies.

Run: python3 verify_vectors.py

Each verification can be cross-checked against:
- WhatsOnChain: https://whatsonchain.com
- Blockchair: https://blockchair.com/bitcoin-sv
- BSV node RPC: bitcoin-cli
"""

import hashlib
import sys

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def sha256(data: bytes) -> bytes:
    """Single SHA-256 hash."""
    return hashlib.sha256(data).digest()

def sha256d(data: bytes) -> bytes:
    """Double SHA-256 hash (Bitcoin standard)."""
    return sha256(sha256(data))

def reverse_bytes(data: bytes) -> bytes:
    """Reverse byte order (internal <-> display format)."""
    return data[::-1]

def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)

def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()

def compute_block_hash(header_hex: str) -> str:
    """
    Compute block hash from 80-byte header.
    Returns display format (reversed, leading zeros).
    """
    header_bytes = hex_to_bytes(header_hex)
    assert len(header_bytes) == 80, f"Header must be 80 bytes, got {len(header_bytes)}"
    hash_bytes = sha256d(header_bytes)
    return bytes_to_hex(reverse_bytes(hash_bytes))

def compute_txid(raw_tx_hex: str) -> str:
    """
    Compute TXID from raw transaction.
    Returns display format (reversed).
    """
    tx_bytes = hex_to_bytes(raw_tx_hex)
    hash_bytes = sha256d(tx_bytes)
    return bytes_to_hex(reverse_bytes(hash_bytes))

def extract_merkle_root(header_hex: str) -> str:
    """
    Extract Merkle root from header bytes 36-68.
    Returns display format (reversed).
    """
    header_bytes = hex_to_bytes(header_hex)
    merkle_internal = header_bytes[36:68]
    return bytes_to_hex(reverse_bytes(merkle_internal))

def extract_nbits(header_hex: str) -> int:
    """Extract nBits from header bytes 72-76 (little-endian)."""
    header_bytes = hex_to_bytes(header_hex)
    nbits_bytes = header_bytes[72:76]
    return int.from_bytes(nbits_bytes, 'little')

def nbits_to_target(nbits: int) -> int:
    """Convert nBits compact format to full 256-bit target."""
    exponent = (nbits >> 24) & 0xff
    mantissa = nbits & 0x7fffff
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    else:
        return mantissa << (8 * (exponent - 3))

def verify_pow(header_hex: str) -> bool:
    """Verify block header proof-of-work: hash <= target."""
    block_hash = compute_block_hash(header_hex)
    hash_int = int(block_hash, 16)
    nbits = extract_nbits(header_hex)
    target = nbits_to_target(nbits)
    return hash_int <= target

def compute_merkle_step(left: bytes, right: bytes) -> bytes:
    """Compute one step of Merkle tree: SHA256d(left || right)."""
    return sha256d(left + right)

def verify_merkle_proof(txid: str, proof: list, expected_root: str) -> bool:
    """
    Verify Merkle proof connects TXID to Merkle root.
    
    Args:
        txid: Transaction ID (display format)
        proof: List of {"hash": "...", "pos": "L"|"R"} - hash is INTERNAL byte order
        expected_root: Expected Merkle root (display format)
    
    Returns:
        True if proof is valid
    """
    # Start with TXID in internal byte order
    current = reverse_bytes(hex_to_bytes(txid))
    
    for node in proof:
        # Handle wildcard (self-duplication)
        if node["hash"] == "*":
            sibling = current
        else:
            # Sibling hash is already in internal byte order
            sibling = hex_to_bytes(node["hash"])
        
        if node["pos"] == "L":
            # Sibling is on left
            current = compute_merkle_step(sibling, current)
        else:
            # Sibling is on right
            current = compute_merkle_step(current, sibling)
    
    # Convert result to display format
    computed_root = bytes_to_hex(reverse_bytes(current))
    return computed_root.lower() == expected_root.lower()


def check_merkle_proof_safe(proof: list) -> bool:
    """
    Check if a Merkle proof is safe from CVE-2012-2459 attacks.
    
    CVE-2012-2459: A malicious peer could construct a valid-looking Merkle proof
    for a non-existent transaction by exploiting the duplication of odd nodes.
    
    This function checks for:
    1. Adjacent duplicate hashes (same hash at consecutive levels)
    2. Wildcards at non-leaf positions
    3. Wildcards with incorrect position (must be R)
    4. Multiple wildcards (only one self-duplication makes sense)
    
    Args:
        proof: Merkle proof list
        
    Returns:
        True if proof structure is safe
    """
    if not isinstance(proof, list):
        return False
    
    wildcard_count = 0
    prev_hash = None
    
    for i, step in enumerate(proof):
        # Basic structure check
        if not isinstance(step, dict):
            return False
        if "hash" not in step or "pos" not in step:
            return False
        
        h = step["hash"]
        pos = step["pos"]
        
        # Check 1: Wildcard constraints
        if h == "*":
            wildcard_count += 1
            
            # Only one wildcard allowed
            if wildcard_count > 1:
                return False
            
            # Wildcard only valid at leaf level (index 0)
            if i != 0:
                return False
            
            # Wildcard must have position R (self on left, duplicate on right)
            if pos != "R":
                return False
        
        # Check 2: No adjacent duplicate hashes
        if h != "*" and prev_hash is not None and h == prev_hash:
            return False
        
        prev_hash = h
    
    return True

# =============================================================================
# TEST VECTORS (from lib/mainnet-vectors.js)
# =============================================================================

VECTORS = {
    "vector1": {
        "description": "Genesis Block (Block 0)",
        "txid": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        "block_hash": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        "block_height": 0,
        "block_header": "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
        "merkle_root": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        "merkle_proof": [],  # Single-tx block: TXID == Merkle root
        "raw_tx": "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
    },
    
    "vector2": {
        "description": "Block 1 - First mined block after genesis",
        "txid": "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098",
        "block_hash": "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
        "block_height": 1,
        "block_header": "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
        "merkle_root": "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098",
        "merkle_proof": [],  # Single-tx block
        "raw_tx": "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"
    },
    
    "vector3": {
        "description": "Block 170 - First person-to-person transaction",
        "txid": "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082",
        "block_hash": "00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee",
        "block_height": 170,
        "block_header": "0100000055bd840a78798ad0da853f68974f3d183e2bd1db6a842c1feecf222a00000000ff104ccb05421ab93e63f8c3ce5c2c2e9dbb37de2764b3a3175c8166562cac7d51b96a49ffff001d283e9e70",
        "merkle_root": "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff",
        # Sibling hash in INTERNAL byte order (reversed from display txid)
        "merkle_proof": [
            {"hash": "169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f4", "pos": "R"}
        ],
        "raw_tx": None  # Not provided
    },
    
    "checkpoint": {
        "description": "Checkpoint Block 935,000",
        "block_hash": "000000000000000014dd029be96be37223e04f66f379dc4eed0f071a73c1f7aa",
        "block_height": 935000,
        "nbits": 0x1d2a0000
    }
}

# =============================================================================
# VERIFICATION TESTS
# =============================================================================

def run_tests():
    """Run all verification tests."""
    print("=" * 70)
    print("BSV MAINNET TEST VECTOR VERIFICATION")
    print("=" * 70)
    print()
    
    passed = 0
    failed = 0
    
    # -------------------------------------------------------------------------
    # VECTOR 1: Genesis Block
    # -------------------------------------------------------------------------
    print("VECTOR 1: Genesis Block (Block 0)")
    print("-" * 50)
    v1 = VECTORS["vector1"]
    
    # Test 1.1: TXID from raw transaction
    computed_txid = compute_txid(v1["raw_tx"])
    if computed_txid == v1["txid"]:
        print(f"  ✓ TXID: {computed_txid[:20]}...")
        passed += 1
    else:
        print(f"  ✗ TXID mismatch!")
        print(f"    Expected: {v1['txid']}")
        print(f"    Got:      {computed_txid}")
        failed += 1
    
    # Test 1.2: Block hash from header
    computed_hash = compute_block_hash(v1["block_header"])
    if computed_hash == v1["block_hash"]:
        print(f"  ✓ Block hash: {computed_hash[:20]}...")
        passed += 1
    else:
        print(f"  ✗ Block hash mismatch!")
        print(f"    Expected: {v1['block_hash']}")
        print(f"    Got:      {computed_hash}")
        failed += 1
    
    # Test 1.3: PoW verification
    if verify_pow(v1["block_header"]):
        print(f"  ✓ Proof-of-work valid")
        passed += 1
    else:
        print(f"  ✗ Proof-of-work INVALID")
        failed += 1
    
    # Test 1.4: Single-tx Merkle property
    extracted_root = extract_merkle_root(v1["block_header"])
    if extracted_root == v1["txid"]:
        print(f"  ✓ Single-tx block: TXID == Merkle root")
        passed += 1
    else:
        print(f"  ✗ Single-tx Merkle property failed!")
        failed += 1
    
    # Test 1.5: Coinbase message
    raw_tx_bytes = hex_to_bytes(v1["raw_tx"])
    expected_msg = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    if expected_msg.encode('ascii') in raw_tx_bytes:
        print(f"  ✓ Coinbase message verified")
        passed += 1
    else:
        print(f"  ✗ Coinbase message not found!")
        failed += 1
    
    print()
    
    # -------------------------------------------------------------------------
    # VECTOR 2: Block 1
    # -------------------------------------------------------------------------
    print("VECTOR 2: Block 1 (First mined block)")
    print("-" * 50)
    v2 = VECTORS["vector2"]
    
    # Test 2.1: TXID from raw transaction
    computed_txid = compute_txid(v2["raw_tx"])
    if computed_txid == v2["txid"]:
        print(f"  ✓ TXID: {computed_txid[:20]}...")
        passed += 1
    else:
        print(f"  ✗ TXID mismatch!")
        print(f"    Expected: {v2['txid']}")
        print(f"    Got:      {computed_txid}")
        failed += 1
    
    # Test 2.2: Block hash from header
    computed_hash = compute_block_hash(v2["block_header"])
    if computed_hash == v2["block_hash"]:
        print(f"  ✓ Block hash: {computed_hash[:20]}...")
        passed += 1
    else:
        print(f"  ✗ Block hash mismatch!")
        print(f"    Expected: {v2['block_hash']}")
        print(f"    Got:      {computed_hash}")
        failed += 1
    
    # Test 2.3: PoW verification
    if verify_pow(v2["block_header"]):
        print(f"  ✓ Proof-of-work valid")
        passed += 1
    else:
        print(f"  ✗ Proof-of-work INVALID")
        failed += 1
    
    # Test 2.4: PrevHash links to genesis
    header_bytes = hex_to_bytes(v2["block_header"])
    prev_hash_internal = header_bytes[4:36]
    prev_hash_display = bytes_to_hex(reverse_bytes(prev_hash_internal))
    if prev_hash_display == v1["block_hash"]:
        print(f"  ✓ PrevHash links to genesis block")
        passed += 1
    else:
        print(f"  ✗ PrevHash mismatch!")
        failed += 1
    
    print()
    
    # -------------------------------------------------------------------------
    # VECTOR 3: Block 170
    # -------------------------------------------------------------------------
    print("VECTOR 3: Block 170 (First P2P transaction)")
    print("-" * 50)
    v3 = VECTORS["vector3"]
    
    # Test 3.1: Block hash from header
    computed_hash = compute_block_hash(v3["block_header"])
    if computed_hash == v3["block_hash"]:
        print(f"  ✓ Block hash: {computed_hash[:20]}...")
        passed += 1
    else:
        print(f"  ✗ Block hash mismatch!")
        print(f"    Expected: {v3['block_hash']}")
        print(f"    Got:      {computed_hash}")
        failed += 1
    
    # Test 3.2: PoW verification
    if verify_pow(v3["block_header"]):
        print(f"  ✓ Proof-of-work valid")
        passed += 1
    else:
        print(f"  ✗ Proof-of-work INVALID")
        failed += 1
    
    # Test 3.3: Merkle root extraction
    extracted_root = extract_merkle_root(v3["block_header"])
    if extracted_root == v3["merkle_root"]:
        print(f"  ✓ Merkle root: {extracted_root[:20]}...")
        passed += 1
    else:
        print(f"  ✗ Merkle root mismatch!")
        print(f"    Expected: {v3['merkle_root']}")
        print(f"    Got:      {extracted_root}")
        failed += 1
    
    # Test 3.4: Merkle proof verification
    if verify_merkle_proof(v3["txid"], v3["merkle_proof"], v3["merkle_root"]):
        print(f"  ✓ Merkle proof valid ({len(v3['merkle_proof'])} node)")
        passed += 1
    else:
        print(f"  ✗ Merkle proof INVALID")
        failed += 1
    
    print()
    
    # -------------------------------------------------------------------------
    # CHECKPOINT: Block 935,000
    # -------------------------------------------------------------------------
    print("CHECKPOINT: Block 935,000")
    print("-" * 50)
    cp = VECTORS["checkpoint"]
    
    # Test 3.1: nBits target computation
    target = nbits_to_target(cp["nbits"])
    if target > 0:
        print(f"  ✓ nBits 0x{cp['nbits']:08x} → target valid")
        passed += 1
    else:
        print(f"  ✗ nBits target computation failed!")
        failed += 1
    
    # Test 3.2: Block hash format (must have leading zeros for BSV difficulty)
    if cp["block_hash"].startswith("00000000"):
        print(f"  ✓ Block hash has expected leading zeros")
        passed += 1
    else:
        print(f"  ✗ Block hash format unexpected!")
        failed += 1
    
    print()
    
    # -------------------------------------------------------------------------
    # INVALID VECTOR TESTS (must fail)
    # -------------------------------------------------------------------------
    print("INVALID VECTORS (must fail verification)")
    print("-" * 50)
    
    # Test 4.1: Corrupted Merkle proof (using v3 data with corrupted proof)
    corrupted_proof = [
        {"hash": "169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f5", "pos": "R"}  # Last byte changed
    ]
    if not verify_merkle_proof(v3["txid"], corrupted_proof, v3["merkle_root"]):
        print(f"  ✓ Corrupted Merkle proof correctly REJECTED")
        passed += 1
    else:
        print(f"  ✗ ERROR: Corrupted Merkle proof was accepted!")
        failed += 1
    
    # Test 4.2: Invalid PoW header (genesis with nonce=0)
    invalid_pow_header = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d00000000"
    if not verify_pow(invalid_pow_header):
        print(f"  ✓ Invalid PoW header correctly REJECTED")
        passed += 1
    else:
        print(f"  ✗ ERROR: Invalid PoW header was accepted!")
        failed += 1
    
    # Test 4.3: TXID mismatch
    wrong_txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    computed = compute_txid(v1["raw_tx"])
    if computed != wrong_txid:
        print(f"  ✓ TXID mismatch correctly detected")
        passed += 1
    else:
        print(f"  ✗ ERROR: TXID mismatch not detected!")
        failed += 1
    
    print()
    
    # -------------------------------------------------------------------------
    # CVE-2012-2459 TESTS
    # -------------------------------------------------------------------------
    print("CVE-2012-2459 PROTECTION TESTS")
    print("-" * 50)
    
    # Test 5.1: Adjacent duplicate hashes
    duplicate_proof = [
        {"hash": "169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f4", "pos": "R"},
        {"hash": "169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f4", "pos": "R"}
    ]
    if not check_merkle_proof_safe(duplicate_proof):
        print(f"  ✓ Adjacent duplicates correctly REJECTED")
        passed += 1
    else:
        print(f"  ✗ ERROR: Adjacent duplicates accepted!")
        failed += 1
    
    # Test 5.2: Wildcard at non-leaf position
    wildcard_nonleaf = [
        {"hash": "169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f4", "pos": "R"},
        {"hash": "*", "pos": "R"}
    ]
    if not check_merkle_proof_safe(wildcard_nonleaf):
        print(f"  ✓ Non-leaf wildcard correctly REJECTED")
        passed += 1
    else:
        print(f"  ✗ ERROR: Non-leaf wildcard accepted!")
        failed += 1
    
    # Test 5.3: Wildcard with wrong position
    wildcard_wrong_pos = [
        {"hash": "*", "pos": "L"}  # Must be R
    ]
    if not check_merkle_proof_safe(wildcard_wrong_pos):
        print(f"  ✓ Wildcard pos=L correctly REJECTED")
        passed += 1
    else:
        print(f"  ✗ ERROR: Wildcard pos=L accepted!")
        failed += 1
    
    # Test 5.4: Multiple wildcards
    multiple_wildcards = [
        {"hash": "*", "pos": "R"},
        {"hash": "*", "pos": "R"}
    ]
    if not check_merkle_proof_safe(multiple_wildcards):
        print(f"  ✓ Multiple wildcards correctly REJECTED")
        passed += 1
    else:
        print(f"  ✗ ERROR: Multiple wildcards accepted!")
        failed += 1
    
    # Test 5.5: Valid wildcard (leaf, pos=R) should pass
    valid_wildcard = [
        {"hash": "*", "pos": "R"}
    ]
    if check_merkle_proof_safe(valid_wildcard):
        print(f"  ✓ Valid wildcard (leaf, pos=R) correctly ACCEPTED")
        passed += 1
    else:
        print(f"  ✗ ERROR: Valid wildcard rejected!")
        failed += 1
    
    print()
    
    # -------------------------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------------------------
    print("=" * 70)
    total = passed + failed
    if failed == 0:
        print(f"✓ ALL {total} TESTS PASSED")
    else:
        print(f"✗ {failed} OF {total} TESTS FAILED")
    print("=" * 70)
    
    # -------------------------------------------------------------------------
    # CROSS-VERIFICATION URLS
    # -------------------------------------------------------------------------
    print()
    print("CROSS-VERIFICATION URLS:")
    print("-" * 50)
    print()
    print("Vector 1 - Transaction:")
    print(f"  https://whatsonchain.com/tx/{v1['txid']}")
    print(f"  https://blockchair.com/bitcoin-sv/transaction/{v1['txid']}")
    print()
    print("Vector 1 - Block:")
    print(f"  https://whatsonchain.com/block-height/{v1['block_height']}")
    print()
    print("Vector 2 - Genesis Block:")
    print(f"  https://whatsonchain.com/block-height/0")
    print()
    print("Checkpoint - Block 935,000:")
    print(f"  https://whatsonchain.com/block-height/935000")
    print()
    
    return failed == 0

# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
