'use strict';
/*
 * test/oracle-beef.js - an INDEPENDENT BEEF / Atomic-BEEF (BRC-62 / BRC-64 / BRC-74 / BRC-95)
 * interpreter, written from the wire format for differential testing against lib/beef.js.
 *
 * INDEPENDENCE (Invariant G): this file imports NOTHING from lib/. It does not require
 * lib/beef.js, lib/bump.js, lib/crypto.js, lib/encoding.js, or @bsv/sdk. Every primitive here
 * - the byte reader and bounds checks, varint decode, transaction walker, txid derivation,
 * BUMP binary decode, Merkle fold, and the BRC-95 subject/ancestry rules - is implemented
 * from scratch. The only cryptographic dependency is Node's native `crypto` (SHA-256), which
 * is a primitive, not BEEF interpretation logic. A test asserts this module's require graph
 * touches no lib/ file (see fuzz-beef-oracle.js, Invariant G).
 *
 * Malformed/truncated input throws OracleMalformed (typed); a proven-tx binding that does not
 * hold throws OracleContradicted. Neither is an uncaught generic exception.
 */
const crypto = require('crypto');

class OracleMalformed extends Error { constructor(m) { super(m); this.name = 'OracleMalformed'; } }
class OracleContradicted extends Error { constructor(m) { super(m); this.name = 'OracleContradicted'; } }

// ---- independent primitives --------------------------------------------------------------
function sha256(b) { return crypto.createHash('sha256').update(b).digest(); }
function sha256d(b) { return sha256(sha256(b)); }
function toHex(u8) { return Buffer.from(u8).toString('hex'); }
function fromHex(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) throw new OracleMalformed('bad hex');
  return Buffer.from(hex, 'hex');
}
function reverse(u8) { const b = Buffer.from(u8); b.reverse(); return b; }
function txidOf(rawBuf) { return toHex(reverse(sha256d(rawBuf))); } // display hex

// bounds-checked reader (throws OracleMalformed past end)
class Reader {
  constructor(buf) { this.buf = buf; this.pos = 0; }
  u8() { if (this.pos + 1 > this.buf.length) throw new OracleMalformed('read u8 past end'); return this.buf[this.pos++]; }
  bytes(n) { if (n < 0 || this.pos + n > this.buf.length) throw new OracleMalformed('read ' + n + ' past end'); const s = this.buf.subarray(this.pos, this.pos + n); this.pos += n; return s; }
  peekEq(arr) { if (this.pos + arr.length > this.buf.length) return false; for (let i = 0; i < arr.length; i++) if (this.buf[this.pos + i] !== arr[i]) return false; return true; }
  varInt() {
    const first = this.u8();
    if (first < 0xfd) return first;
    if (first === 0xfd) { const b = this.bytes(2); return b[0] | (b[1] << 8); }
    if (first === 0xfe) { const b = this.bytes(4); return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] * 0x1000000)) >>> 0; }
    // 0xff -> 8-byte; use BigInt then bound to a sane range (a count this large is malformed here)
    const b = this.bytes(8); let v = 0n; for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
    if (v > 0xffffffffn) throw new OracleMalformed('varint too large for a BEEF count/length');
    return Number(v);
  }
}

const ATOMIC_PREFIX = [0x01, 0x01, 0x01, 0x01];
const BEEF_VERSION = [0x01, 0x00, 0xbe, 0xef];

// ---- independent raw-transaction walker (returns txid + inputs) ---------------------------
function readRawTx(r) {
  const start = r.pos;
  r.bytes(4);                          // version
  const nIn = r.varInt(), inputs = [];
  for (let i = 0; i < nIn; i++) {
    const prevTxid = toHex(reverse(r.bytes(32)));
    const b = r.bytes(4); const vout = (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] * 0x1000000)) >>> 0;
    const sLen = r.varInt(); r.bytes(sLen);   // scriptSig
    r.bytes(4);                                // sequence
    inputs.push({ prevTxid, vout });
  }
  const nOut = r.varInt();
  for (let i = 0; i < nOut; i++) { r.bytes(8); const oLen = r.varInt(); r.bytes(oLen); }
  r.bytes(4);                          // locktime
  const raw = r.buf.subarray(start, r.pos);
  return { rawHex: toHex(raw), txid: txidOf(raw), inputs };
}

// ---- independent BRC-74 BUMP binary decode -----------------------------------------------
function readBump(r) {
  const blockHeight = r.varInt();
  const treeHeight = r.u8();
  if (treeHeight > 64) throw new OracleMalformed('BUMP treeHeight implausible');
  const path = [];
  for (let lvl = 0; lvl < treeHeight; lvl++) {
    const n = r.varInt(), leaves = [];
    for (let i = 0; i < n; i++) {
      const offset = r.varInt();
      const flags = r.u8();
      const leaf = { offset };
      if (flags & 1) leaf.duplicate = true;
      else { if (flags & 2) leaf.txid = true; leaf.hash = toHex(reverse(r.bytes(32))); }
      leaves.push(leaf);
    }
    leaves.sort((a, b) => a.offset - b.offset);
    path.push(leaves);
  }
  return { blockHeight, path };
}

// ---- independent Merkle fold: reconstruct the BUMP root for a txid ------------------------
// display-hex in/out; hashing is done on natural (reversed) bytes, pairing by offset parity.
function hashPairDisplay(aDisp, bDisp) {
  const cat = Buffer.concat([reverse(fromHex(aDisp)), reverse(fromHex(bDisp))]);
  return toHex(reverse(sha256d(cat)));
}
function bumpRoot(bump, txidDisplay) {
  const path = bump.path;
  if (!path || !path.length) {
    // depth-0: single-tx block, root == txid
    return txidDisplay;
  }
  // find the txid at level 0 to get its index
  let index = -1;
  for (const leaf of path[0]) if (leaf.hash && leaf.hash.toLowerCase() === txidDisplay.toLowerCase()) { index = leaf.offset; break; }
  if (index < 0) throw new OracleContradicted('txid not present in BUMP level-0');
  let current = txidDisplay;
  for (let height = 0; height < path.length; height++) {
    const siblingOffset = (index >> height) ^ 1;
    const level = path[height];
    let sib = null;
    for (const leaf of level) if (leaf.offset === siblingOffset) { sib = leaf; break; }
    if (!sib) {
      // a missing sibling at this height with no duplicate flag is malformed for our purposes
      throw new OracleContradicted('missing sibling at height ' + height);
    }
    const sibHash = sib.duplicate ? current : sib.hash;
    const left = (index >> height) & 1 ? sibHash : current;
    const right = (index >> height) & 1 ? current : sibHash;
    current = hashPairDisplay(left, right);
  }
  return current;
}

// ---- independent BRC-95 subject/ancestry validation --------------------------------------
function validateAtomicSubject(txs, subject) {
  if (!txs || !txs.length) throw new OracleMalformed('Atomic BEEF: empty container');
  const byId = {}; txs.forEach(t => { byId[t.txid] = t; });
  if (!byId[subject]) throw new OracleContradicted('Atomic BEEF: subject not present');
  if (txs[txs.length - 1].txid !== subject) throw new OracleContradicted('Atomic BEEF: subject not last');
  const reach = {}; reach[subject] = true; const stack = [subject]; let steps = 0;
  while (stack.length) {
    if (++steps > 1000000) throw new OracleMalformed('Atomic BEEF: ancestry walk bound exceeded');
    const cur = byId[stack.pop()]; if (!cur) continue;
    (cur.inputs || []).forEach(inp => { if (byId[inp.prevTxid] && !reach[inp.prevTxid]) { reach[inp.prevTxid] = true; stack.push(inp.prevTxid); } });
  }
  txs.forEach(t => { if (!reach[t.txid]) throw new OracleContradicted('Atomic BEEF: ' + t.txid + ' is neither subject nor an ancestor'); });
}

// ---- top-level independent BEEF parse ----------------------------------------------------
function parseBeef(hex) {
  const r = new Reader(fromHex(hex));
  let atomic = null;
  if (r.peekEq(ATOMIC_PREFIX)) { r.bytes(4); atomic = toHex(reverse(r.bytes(32))); }
  if (!r.peekEq(BEEF_VERSION)) throw new OracleMalformed('not a BEEF stream (missing 0100BEEF marker)');
  r.bytes(4);
  const nBumps = r.varInt(), bumps = [];
  for (let i = 0; i < nBumps; i++) bumps.push(readBump(r));
  const nTx = r.varInt(), txs = [];
  for (let i = 0; i < nTx; i++) {
    const tx = readRawTx(r);
    const hasBump = r.u8();
    tx.bumpIndex = hasBump ? r.varInt() : null;
    txs.push(tx);
  }
  if (r.pos !== r.buf.length) throw new OracleMalformed('trailing bytes after transactions');
  if (atomic !== null) validateAtomicSubject(txs, atomic);
  return { atomicSubject: atomic, bumps, transactions: txs };
}

module.exports = { parseBeef, bumpRoot, txidOf, validateAtomicSubject, OracleMalformed, OracleContradicted, _sha256d: sha256d };
