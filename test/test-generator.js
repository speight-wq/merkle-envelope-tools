'use strict';
const fs = require('fs');
const vm = require('vm');
const crypto = require('crypto');
const BUMP = require('./bump.js');
const BEEF = require('./beef.js');

// ---- pull the ACTUAL emit helpers out of the edited generator.html ---------
const gsrc = fs.readFileSync('./generator.html', 'utf8');
const a = gsrc.indexOf('function headerMerkleRootDisplay');
const b = gsrc.indexOf('// Multi-Source API Configuration');
if (a < 0 || b < 0) throw new Error('could not locate emit helpers in generator.html');
const helpersSrc = gsrc.slice(a, b);
const gctx = { BUMP, console };
vm.createContext(gctx);
vm.runInContext(helpersSrc, gctx);
const { tscToBump, attachBump, headerMerkleRootDisplay } = gctx;
if (!tscToBump || !attachBump) throw new Error('emit helpers not exposed from generator.html');

// ---- independent Bitcoin Merkle oracle (Node crypto) -----------------------
const sha256d = (buf) => crypto.createHash('sha256').update(crypto.createHash('sha256').update(buf).digest()).digest();
const toDisplay = (n) => Buffer.from(n).reverse().toString('hex');
const toNatural = (h) => Buffer.from(h, 'hex').reverse();
const randTxid = () => crypto.randomBytes(32).toString('hex');

function buildTree(txids) {
  let cur = txids.map(toNatural);
  const levels = [cur.slice()];
  while (cur.length > 1) {
    const next = [];
    for (let i = 0; i < cur.length; i += 2) next.push(sha256d(Buffer.concat([cur[i], (i + 1 < cur.length) ? cur[i + 1] : cur[i]])));
    levels.push(next.slice());
    cur = next;
  }
  return { levels, treeHeight: levels.length - 1, rootDisplay: toDisplay(levels[levels.length - 1][0]) };
}
// TSC proof (siblings bottom-to-top, display order, '*' for duplicate)
function tscNodes(tree, idx) {
  const nodes = [];
  for (let h = 0; h < tree.treeHeight; h++) {
    const pos = idx >> h, sib = pos ^ 1;
    nodes.push(sib < tree.levels[h].length ? toDisplay(tree.levels[h][sib]) : '*');
  }
  return nodes;
}
function buildHeader(merkleRootDisplay) {
  const mrLE = merkleRootDisplay.match(/../g).reverse().join('');
  return '01000000' + '00'.repeat(32) + mrLE + '00000000' + '00000000' + '00000000';
}

let pass = 0, fail = 0; const fails = [];
const assert = (c, m) => { c ? pass++ : (fail++, fails.push(m)); };

// ===========================================================================
// TEST 1: TSC -> BUMP conversion matches the independent Merkle oracle
// ===========================================================================
const SHAPES = [2, 3, 4, 5, 7, 8, 9, 16, 17, 33, 64, 100, 256, 1000, 2049, 4096];
let n1 = 0;
for (const n of SHAPES) {
  for (let t = 0; t < 10; t++) {
    const txids = Array.from({ length: n }, randTxid);
    const tree = buildTree(txids);
    const idx = (t === 0) ? 0 : Math.floor(Math.random() * n); // include index 0
    const nodes = tscNodes(tree, idx);
    const bumpObj = tscToBump(txids[idx], idx, nodes, 800000 + n);
    assert(BUMP.merkleRoot(bumpObj, txids[idx]) === tree.rootDisplay,
      `TSC->BUMP root n=${n} idx=${idx}`);
    // round-trips through bump.js serializer
    assert(BUMP.toHex(BUMP.fromHex(BUMP.toHex(bumpObj))) === BUMP.toHex(bumpObj),
      `TSC->BUMP serialize round-trip n=${n} idx=${idx}`);
    n1++;
  }
}
console.log(`TEST 1  TSC->BUMP vs independent oracle : ${n1} conversions across ${SHAPES.length} shapes`);

// ===========================================================================
// TEST 2: attachBump self-verify guard (attaches on match, refuses on mismatch)
// ===========================================================================
{
  const txids = Array.from({ length: 40 }, randTxid);
  const tree = buildTree(txids);
  const idx = 5;
  const nodes = tscNodes(tree, idx);
  const goodHeader = buildHeader(tree.rootDisplay);

  const env1 = { txid: txids[idx] };
  attachBump(env1, goodHeader, nodes, idx, 800321);
  assert(!!env1.bump, 'attachBump sets bump when root matches header');

  // wrong header -> must NOT attach
  const badHeader = buildHeader('ff' + tree.rootDisplay.slice(2));
  const env2 = { txid: txids[idx] };
  attachBump(env2, badHeader, nodes, idx, 800321);
  assert(!env2.bump, 'attachBump refuses to attach when header root mismatches');

  // header helper agrees with the source root
  assert(headerMerkleRootDisplay(goodHeader) === tree.rootDisplay, 'headerMerkleRootDisplay correct');
}
console.log('TEST 2  attachBump self-verify guard    : done');

// ===========================================================================
// TEST 3: end-to-end — generator emits bump, the WIRED verifier accepts it
// ===========================================================================
{
  // real tx as the client leaf so the verifier's txid/rawTx check also passes
  const parsed = BEEF.parse(BEEF.VECTOR.hex);
  const tx0 = parsed.transactions[0];
  const tree = buildTree([tx0.txid, randTxid(), randTxid(), randTxid(), randTxid()]);
  const idx = 0;
  const nodes = tscNodes(tree, idx);
  const header = buildHeader(tree.rootDisplay);

  const envelope = { txid: tx0.txid, rawTx: tx0.rawHex, blockHeader: header, vout: 0, satoshis: 1000, confirmations: 100 };
  attachBump(envelope, header, nodes, idx, 800500);
  assert(!!envelope.bump, 'generator produced a bump field');

  // run the actual wired verifier inline script on this envelope
  const vhtml = fs.readFileSync('./verifier.html', 'utf8');
  const vscript = vhtml.slice(vhtml.indexOf('(function() {'), vhtml.indexOf('})();', vhtml.indexOf('(function() {')) + 5);
  const hash256 = (hex) => sha256d(Buffer.from(hex, 'hex'));
  const els = {};
  const el = (id) => (els[id] || (els[id] = {
    _tc: '', _html: '', _v: '', addEventListener(e, f) { this._click = f; },
    classList: { add() {}, remove() {} },
    get value() { return this._v; }, set value(x) { this._v = x; },
    set textContent(x) { this._tc = x; }, set className(x) {}, set innerHTML(x) { this._html = x; }
  }));
  const vctx = {
    document: { getElementById: el }, BUMP, BEEF, Date, console,
    hash256, bytesToHex: (b) => Buffer.from(b).toString('hex'),
    reverseHex: (h) => h.match(/../g).reverse().join(''),
    parseHeader: () => ({ timestamp: 0, merkleRoot: 'x' }), verifyPoW: () => true,
    hashHeader: () => '00'.repeat(32), checkMerkleProofSafe: () => true, verifyMerkleProof: () => true
  };
  vm.createContext(vctx);
  vm.runInContext(vscript, vctx);
  vctx.document.getElementById('envelope-input').value = JSON.stringify(envelope);
  ['result-box', 'result-title', 'checks', 'details', 'result-section'].forEach(id => vctx.document.getElementById(id));
  vctx.document.getElementById('verify-btn')._click();
  const title = els['result-title']._tc, checks = (els['checks']._html || '').replace(/<[^>]+>/g, ' ');
  assert(/VALID MERKLE PROOF/.test(title), 'wired verifier returns VALID for generator-emitted bump');
  assert(/BUMP Merkle root matches block header/.test(checks), 'verifier reports BUMP root match');
}
console.log('TEST 3  generator -> verifier round trip: done');

console.log('\n----------------------------------------');
console.log(`PASSED: ${pass}   FAILED: ${fail}`);
if (fail) fails.slice(0, 20).forEach(f => console.log('  - ' + f));
process.exit(fail ? 1 : 0);
