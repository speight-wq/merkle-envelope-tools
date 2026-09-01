/*
 * validate.js — differential validation of bump.js and beef.js against an
 * INDEPENDENT reference implementation (Node's native crypto, standard Bitcoin
 * Merkle construction). Shares no code with the modules under test.
 *
 * Run: node test/validate.js   (from repo root)
 */
'use strict';
const crypto = require('crypto');
const BUMP = require('../lib/bump.js');
const BEEF = require('../lib/beef.js');

// ---- independent primitives -------------------------------------------------
const sha256d = (buf) =>
  crypto.createHash('sha256').update(crypto.createHash('sha256').update(buf).digest()).digest();
const toDisplay = (natBuf) => Buffer.from(natBuf).reverse().toString('hex');
const toNatural = (displayHex) => Buffer.from(displayHex, 'hex').reverse();
const randTxid = () => crypto.randomBytes(32).toString('hex'); // already "display"-ish (random)

// ---- independent Bitcoin Merkle tree (natural byte order) -------------------
// Returns { levels: [ [Buffer,...], ... ], treeHeight, rootDisplay }
function buildTree(txidsDisplay) {
  let cur = txidsDisplay.map(toNatural);
  const levels = [cur.slice()];
  while (cur.length > 1) {
    const next = [];
    for (let i = 0; i < cur.length; i += 2) {
      const left = cur[i];
      const right = (i + 1 < cur.length) ? cur[i + 1] : cur[i]; // duplicate last if odd
      next.push(sha256d(Buffer.concat([left, right])));
    }
    levels.push(next.slice());
    cur = next;
  }
  return { levels, treeHeight: levels.length - 1, rootDisplay: toDisplay(levels[levels.length - 1][0]) };
}

// ---- independent single-client BUMP builder (bump.js JSON shape) ------------
function buildSingleClientBUMP(tree, idx, blockHeight) {
  const { levels, treeHeight } = tree;
  const path = [];
  // level 0: client txid + its sibling
  const lvl0 = [{ offset: idx, txid: true, hash: toDisplay(levels[0][idx]) }];
  const sib0 = idx ^ 1;
  if (sib0 < levels[0].length) lvl0.push({ offset: sib0, hash: toDisplay(levels[0][sib0]) });
  else lvl0.push({ offset: sib0, duplicate: true });
  lvl0.sort((a, b) => a.offset - b.offset);
  path.push(lvl0);
  // levels 1..treeHeight-1: one sibling each
  for (let h = 1; h < treeHeight; h++) {
    const pos = idx >> h;
    const sib = pos ^ 1;
    if (sib < levels[h].length) path.push([{ offset: sib, hash: toDisplay(levels[h][sib]) }]);
    else path.push([{ offset: sib, duplicate: true }]);
  }
  return { blockHeight: blockHeight, path };
}

// ---- independent path-fold (a SECOND oracle, different from full-tree) ------
function foldRoot(tree, idx) {
  const { levels, treeHeight } = tree;
  let working = levels[0][idx]; // natural
  for (let h = 0; h < treeHeight; h++) {
    const pos = idx >> h;
    const sib = pos ^ 1;
    let sibHash;
    if (sib < levels[h].length) sibHash = levels[h][sib];
    else sibHash = working; // duplicate
    working = (pos & 1)
      ? sha256d(Buffer.concat([sibHash, working]))   // working on the right
      : sha256d(Buffer.concat([working, sibHash]));  // working on the left
  }
  return toDisplay(working);
}

// ---------------------------------------------------------------------------
let pass = 0, fail = 0;
const failures = [];
function assert(cond, msg) { if (cond) pass++; else { fail++; failures.push(msg); } }

// ===========================================================================
// TEST 1: BUMP root matches independent oracle across many tree shapes
// ===========================================================================
const SHAPES = [2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 64, 100, 255, 511, 1000, 2048, 4095, 4096];
let bumpChecks = 0;
for (const n of SHAPES) {
  for (let trial = 0; trial < 8; trial++) {
    const txids = Array.from({ length: n }, randTxid);
    const tree = buildTree(txids);

    // sanity: the two independent oracles agree with each other
    for (let k = 0; k < Math.min(n, 6); k++) {
      const idx = (trial === 0 && k === 0) ? 0 : Math.floor(Math.random() * n); // include idx 0
      assert(foldRoot(tree, idx) === tree.rootDisplay,
        `oracle self-consistency n=${n} idx=${idx}`);

      // build a BUMP for this client and check bump.js agrees
      const bump = buildSingleClientBUMP(tree, idx, 800000 + n);
      const got = BUMP.merkleRoot(bump, txids[idx]);
      assert(got === tree.rootDisplay,
        `bump.js root mismatch n=${n} idx=${idx}\n   want ${tree.rootDisplay}\n   got  ${got}`);
      // round-trip the BUMP through bump.js serializer
      assert(BUMP.toHex(BUMP.fromHex(BUMP.toHex(bump))) === BUMP.toHex(bump),
        `bump.js serialize round-trip n=${n} idx=${idx}`);
      bumpChecks++;
    }
  }
}
console.log(`TEST 1  BUMP vs independent Merkle oracle : ${bumpChecks} checks across ${SHAPES.length} tree shapes`);

// ===========================================================================
// TEST 2: bump.js wrong-txid / tamper behaviour
// ===========================================================================
{
  const txids = Array.from({ length: 50 }, randTxid);
  const tree = buildTree(txids);
  const bump = buildSingleClientBUMP(tree, 7, 800123);
  // correct
  assert(BUMP.merkleRoot(bump, txids[7]) === tree.rootDisplay, 'tamper-base correct root');
  // a txid not in the bump must throw
  let threw = false;
  try { BUMP.merkleRoot(bump, randTxid()); } catch (e) { threw = true; }
  assert(threw, 'unknown txid throws rather than returning a bogus root');
  // corrupt a sibling on the path -> different root
  const bad = JSON.parse(JSON.stringify(bump));
  const sibLeaf = bad.path[1].find(l => l.hash); // an internal sibling
  if (sibLeaf) { sibLeaf.hash = 'ff' + sibLeaf.hash.slice(2);
    assert(BUMP.merkleRoot(bad, txids[7]) !== tree.rootDisplay, 'tampered sibling changes root'); }
}
console.log('TEST 2  tamper / unknown-txid behaviour   : done');

// ===========================================================================
// TEST 3: published BRC-74 multi-client vector (independent recompute)
// ===========================================================================
{
  const V = BUMP.VECTOR;
  for (const txid of V.txids) assert(BUMP.merkleRoot(BUMP.fromHex(V.hex), txid) === V.root,
    'BRC-74 vector txid ' + txid);
}
console.log('TEST 3  BRC-74 published vector           : done');

// ===========================================================================
// TEST 4: BEEF tx-walker round-trip across random tx shapes
// ===========================================================================
function varint(n) {
  if (n < 0xfd) return Buffer.from([n]);
  if (n <= 0xffff) return Buffer.concat([Buffer.from([0xfd]), le(n, 2)]);
  if (n <= 0xffffffff) return Buffer.concat([Buffer.from([0xfe]), le(n, 4)]);
  return Buffer.concat([Buffer.from([0xff]), le(n, 8)]);
}
function le(n, bytes) { const b = Buffer.alloc(bytes); let v = n; for (let i = 0; i < bytes; i++) { b[i] = v & 0xff; v = Math.floor(v / 256); } return b; }
function randTx(prevTxid, prevVout) {
  const nIn = 1 + Math.floor(Math.random() * 3);
  const nOut = 1 + Math.floor(Math.random() * 3);
  const parts = [le(1, 4), varint(nIn)];
  for (let i = 0; i < nIn; i++) {
    const pt = (i === 0 && prevTxid) ? toNatural(prevTxid) : crypto.randomBytes(32);
    const vout = (i === 0 && prevTxid) ? le(prevVout, 4) : le(Math.floor(Math.random() * 4), 4);
    const slen = Math.floor(Math.random() * 110); // varying script length: stresses the walker
    parts.push(pt, vout, varint(slen), crypto.randomBytes(slen), le(0xffffffff, 4));
  }
  parts.push(varint(nOut));
  for (let i = 0; i < nOut; i++) {
    const slen = 20 + Math.floor(Math.random() * 15);
    parts.push(le(Math.floor(Math.random() * 1e6), 8), varint(slen), crypto.randomBytes(slen));
  }
  parts.push(le(0, 4));
  return Buffer.concat(parts).toString('hex');
}
let beefChecks = 0;
for (let trial = 0; trial < 200; trial++) {
  const chainLen = 2 + Math.floor(Math.random() * 4);
  const txs = [];
  let prev = null, prevVout = 0;
  for (let i = 0; i < chainLen; i++) {
    const rawHex = randTx(prev, prevVout);
    const txid = BEEF.txidOf(rawHex);
    // cross-check txid against Node crypto directly
    const nodeTxid = Buffer.from(sha256d(Buffer.from(rawHex, 'hex'))).reverse().toString('hex');
    assert(txid === nodeTxid, 'BEEF.txidOf matches Node crypto');
    txs.push({ rawHex, txid });
    prev = txid; prevVout = 0;
  }
  // give the oldest tx a BUMP so it's a "mined" anchor
  const tree = buildTree([txs[0].txid, randTxid(), randTxid(), randTxid()]);
  const bump = buildSingleClientBUMP(tree, 0, 810000 + trial);
  const built = BEEF.build({
    bumps: [bump],
    transactions: txs.map((t, i) => ({ rawHex: t.rawHex, bumpIndex: i === 0 ? 0 : null }))
  });
  // parse back and round-trip
  const parsed = BEEF.parse(built);
  assert(BEEF.build(parsed) === built.toLowerCase(), 'BEEF round-trip byte-identical trial ' + trial);
  assert(parsed.transactions.length === chainLen, 'BEEF tx count preserved');
  assert(parsed.transactions[0].txid === txs[0].txid, 'BEEF oldest txid preserved');
  // atomic wrap/unwrap
  const subject = txs[chainLen - 1].txid;
  const atomic = BEEF.wrapAtomic(built, subject);
  const re = BEEF.parse(atomic);
  assert(re.atomicSubject === subject, 'atomic subject preserved trial ' + trial);
  assert(BEEF.build(re) === built.toLowerCase(), 'atomic body rebuilds trial ' + trial);
  beefChecks++;
}
console.log(`TEST 4  BEEF walker/round-trip            : ${beefChecks} random tx-chains`);

// ===========================================================================
console.log('\n----------------------------------------');
console.log(`PASSED: ${pass}   FAILED: ${fail}`);
if (fail) { console.log('\nFAILURES:'); failures.slice(0, 20).forEach(f => console.log('  - ' + f)); }
process.exit(fail ? 1 : 0);
