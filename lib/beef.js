/*
 * beef.js — BEEF (BRC-62) and Atomic BEEF (BRC-95) reader / writer.
 * Consumes bump.js for Merkle math. Pure vanilla JS, no dependencies.
 *
 * SCOPE (deliberate):
 *   - Parse and serialize the BEEF / Atomic BEEF container.
 *   - Resolve the transaction DAG (txid -> tx, input -> parent).
 *   - Verify MINED inputs by computing their source tx's Merkle root via BUMP,
 *     handing the root back to YOUR header check (embedded header or header set).
 *   - Topologically order transactions when writing (ancestors first, subject last).
 *   - Wrap / unwrap Atomic BEEF (0x01010101 + subject txid).
 *
 * NOT IN SCOPE (on purpose):
 *   - Bitcoin Script evaluation and value-conservation checks for UNMINED ancestors.
 *     Cold-storage spends confirmed UTXOs, so every input has a Merkle proof and the
 *     unmined-ancestor path never triggers. Implementing a script interpreter here
 *     would dwarf the tool and destroy auditability for a case it doesn't hit.
 *     If a tx has no BUMP, this module reports it as "unproven" rather than validating it.
 *
 * Specs: https://bsv.brc.dev/transactions/0062 , https://hub.bsvblockchain.org/brc/transactions/0095
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('./bump.js'));
  else root.BEEF = factory(root.BUMP);
})(typeof self !== 'undefined' ? self : this, function (BUMP) {
  'use strict';
  if (!BUMP) throw new Error('beef.js requires bump.js (BUMP) to be loaded first');

  var BEEF_VERSION = [0x01, 0x00, 0xbe, 0xef];
  var ATOMIC_PREFIX = [0x01, 0x01, 0x01, 0x01];

  // ---- hex helpers -------------------------------------------------
  function fromHex(hex) {
    // Strict: reject odd length / non-hex rather than coercing NaN -> 0 (audit item 9).
    if (typeof hex !== 'string' || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
      throw new Error('BEEF: invalid hex input');
    }
    var a = new Uint8Array(hex.length / 2);
    for (var i = 0; i < a.length; i++) a[i] = parseInt(hex.substr(i * 2, 2), 16);
    return a;
  }
  function toHex(u8) {
    var s = '';
    for (var i = 0; i < u8.length; i++) s += (u8[i] < 16 ? '0' : '') + u8[i].toString(16);
    return s;
  }
  function reverse(u8) {
    var r = new Uint8Array(u8.length);
    for (var i = 0; i < u8.length; i++) r[i] = u8[u8.length - 1 - i];
    return r;
  }
  function sha256d(u8) { return BUMP.sha256(BUMP.sha256(u8)); }
  function txidOf(rawBytes) { return toHex(reverse(sha256d(rawBytes))); } // display hex

  // ---- Reader / Writer (VarInt aware) ------------------------------
  function Reader(u8) { this.buf = u8; this.pos = 0; }
  // Bounds-checked reads (audit item 9): fail closed on truncated/malformed streams.
  Reader.prototype.u8 = function () {
    if (this.pos >= this.buf.length) throw new Error('BEEF: unexpected end of stream');
    return this.buf[this.pos++];
  };
  Reader.prototype.bytes = function (n) {
    if (this.pos + n > this.buf.length) throw new Error('BEEF: read past end of stream');
    var b = this.buf.subarray(this.pos, this.pos + n); this.pos += n; return b;
  };
  Reader.prototype.peekEq = function (arr) {
    for (var i = 0; i < arr.length; i++) if (this.buf[this.pos + i] !== arr[i]) return false;
    return true;
  };
  Reader.prototype.varInt = function () {
    var f = this.u8();
    if (f < 0xfd) return f;
    if (f === 0xfd) { var a = this.u8(), b = this.u8(); return a | (b << 8); }
    if (f === 0xfe) { var c = this.bytes(4); return c[0] | (c[1] << 8) | (c[2] << 16) | (c[3] * 0x1000000); }
    var d = this.bytes(8);
    var lo = d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] * 0x1000000);
    var hi = d[4] | (d[5] << 8) | (d[6] << 16) | (d[7] * 0x1000000);
    return hi * 0x100000000 + lo;
  };

  function Writer() { this.parts = []; }
  Writer.prototype.u8 = function (n) { this.parts.push(new Uint8Array([n & 0xff])); return this; };
  Writer.prototype.bytes = function (u8) { this.parts.push(u8); return this; };
  Writer.prototype.hex = function (h) { this.parts.push(fromHex(h)); return this; };
  Writer.prototype.varInt = function (n) {
    if (n < 0xfd) return this.u8(n);
    if (n <= 0xffff) return this.bytes(new Uint8Array([0xfd, n & 0xff, (n >>> 8) & 0xff]));
    if (n <= 0xffffffff) return this.bytes(new Uint8Array([0xfe, n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]));
    var lo = n >>> 0, hi = Math.floor(n / 0x100000000);
    return this.bytes(new Uint8Array([0xff, lo & 0xff, (lo >>> 8) & 0xff, (lo >>> 16) & 0xff, (lo >>> 24) & 0xff,
                                            hi & 0xff, (hi >>> 8) & 0xff, (hi >>> 16) & 0xff, (hi >>> 24) & 0xff]));
  };
  Writer.prototype.toHex = function () {
    var len = 0, i; for (i = 0; i < this.parts.length; i++) len += this.parts[i].length;
    var out = new Uint8Array(len), o = 0;
    for (i = 0; i < this.parts.length; i++) { out.set(this.parts[i], o); o += this.parts[i].length; }
    return toHex(out);
  };

  // ---- BUMP field read (produces a bump.js-compatible object) -------
  // Kept here so we can consume a BUMP from the middle of a BEEF stream.
  // Serialization/root math still go through bump.js.
  function readBump(r) {
    var blockHeight = r.varInt();
    var treeHeight = r.u8();
    var path = [];
    for (var lvl = 0; lvl < treeHeight; lvl++) {
      var n = r.varInt(), leaves = [];
      for (var i = 0; i < n; i++) {
        var offset = r.varInt();
        var flags = r.u8();
        var leaf = { offset: offset };
        if (flags & 1) leaf.duplicate = true;
        else { if (flags & 2) leaf.txid = true; leaf.hash = toHex(reverse(r.bytes(32))); }
        leaves.push(leaf);
      }
      leaves.sort(function (a, b) { return a.offset - b.offset; });
      path.push(leaves);
    }
    return { blockHeight: blockHeight, path: path };
  }

  // ---- raw tx walker: find its byte length, txid, and inputs -------
  function readRawTx(r) {
    var start = r.pos;
    r.bytes(4); // version
    var nIn = r.varInt(), inputs = [], i;
    for (i = 0; i < nIn; i++) {
      var prevTxid = toHex(reverse(r.bytes(32)));
      var vout = r.bytes(4); vout = vout[0] | (vout[1] << 8) | (vout[2] << 16) | (vout[3] * 0x1000000);
      var sLen = r.varInt(); r.bytes(sLen);
      r.bytes(4); // sequence
      inputs.push({ prevTxid: prevTxid, vout: vout });
    }
    var nOut = r.varInt();
    for (i = 0; i < nOut; i++) { r.bytes(8); var oLen = r.varInt(); r.bytes(oLen); }
    r.bytes(4); // locktime
    var end = r.pos;
    var raw = r.buf.subarray(start, end);
    return { rawHex: toHex(raw), txid: txidOf(raw), inputs: inputs };
  }

  // ---- parse a full BEEF (or Atomic BEEF) --------------------------
  function parse(hex) {
    var r = new Reader(fromHex(hex));
    var atomic = null;
    if (r.peekEq(ATOMIC_PREFIX)) {
      r.bytes(4);
      atomic = toHex(reverse(r.bytes(32))); // subject txid, display hex
    }
    if (!r.peekEq(BEEF_VERSION)) throw new Error('not a BEEF stream (missing 0100BEEF marker)');
    r.bytes(4); // version

    var nBumps = r.varInt(), bumps = [];
    for (var i = 0; i < nBumps; i++) bumps.push(readBump(r));

    var nTx = r.varInt(), txs = [];
    for (i = 0; i < nTx; i++) {
      var tx = readRawTx(r);
      var hasBump = r.u8();
      tx.bumpIndex = hasBump ? r.varInt() : null;
      txs.push(tx);
    }
    // Reject trailing garbage after the last transaction (audit item 9).
    if (r.pos !== r.buf.length) throw new Error('BEEF: ' + (r.buf.length - r.pos) + ' trailing byte(s) after transactions');
    return { atomicSubject: atomic, bumps: bumps, transactions: txs };
  }

  // ---- scoped verification: prove MINED txs via their BUMP ----------
  // isValidRoot(rootDisplayHex, blockHeight) -> boolean, supplied by you.
  //   For the hybrid path, compare against the header you already embed.
  //   NOTE: BUMP.merkleRoot returns DISPLAY hex; a header's root field is
  //   NATURAL byte order — use BUMP.reverseHex() before comparing.
  function verifyMined(beef, isValidRoot) {
    // Require the root validator (audit item 7/9). Calling verifyMined without it
    // previously stamped every proven tx valid with NO header check at all — a
    // silent accept. A caller that genuinely wants "compute roots, don't check"
    // must opt in explicitly with the sentinel below.
    if (typeof isValidRoot !== 'function') {
      if (isValidRoot === verifyMined.UNSAFE_SKIP_ROOT_CHECK) {
        isValidRoot = function () { return true; };
      } else {
        throw new Error('verifyMined requires an isValidRoot(root, height) callback');
      }
    }

    var byId = {};
    beef.transactions.forEach(function (t) { byId[t.txid] = t; });

    var report = { proven: [], unproven: [], allProvenValid: true, links: [] };

    beef.transactions.forEach(function (t) {
      if (t.bumpIndex === null || t.bumpIndex === undefined) {
        report.unproven.push(t.txid);
        return;
      }
      var bump = beef.bumps[t.bumpIndex];
      if (!bump) throw new Error('tx references missing BUMP index ' + t.bumpIndex);
      // txid must appear as a client txid leaf at level 0
      var present = bump.path[0].some(function (l) { return l.hash === t.txid; });
      if (!present) throw new Error('tx ' + t.txid + ' not found in its BUMP level-0 leaves');
      var rootDisplay = BUMP.merkleRoot(bump, t.txid);
      var ok = !!isValidRoot(rootDisplay, bump.blockHeight);
      report.proven.push({ txid: t.txid, root: rootDisplay, blockHeight: bump.blockHeight, valid: ok });
      if (!ok) report.allProvenValid = false;
    });

    // Honest aggregate (audit item 9): "all proven valid" must not read true when
    // nothing was proven or when some tx carries no BUMP. Callers that checked only
    // allProvenValid previously accepted an entirely-unproven bundle.
    if (report.proven.length === 0 || report.unproven.length > 0) {
      report.allProvenValid = false;
    }

    // record which inputs resolve to a parent present in this BEEF
    beef.transactions.forEach(function (t) {
      t.inputs.forEach(function (inp) {
        report.links.push({ tx: t.txid, spendsParent: inp.prevTxid, parentInBeef: !!byId[inp.prevTxid] });
      });
    });
    return report;
  }
  // Explicit opt-out sentinel for the rare "compute roots without checking" case.
  verifyMined.UNSAFE_SKIP_ROOT_CHECK = { __unsafeSkipRootCheck: true };

  // ---- topological order (Kahn): ancestors first, subject last ------
  function topoSort(txs) {
    var byId = {}, i;
    txs.forEach(function (t) { byId[t.txid] = t; });
    var inDegree = {}, adj = {};
    txs.forEach(function (t) { inDegree[t.txid] = 0; adj[t.txid] = []; });
    txs.forEach(function (t) {
      t.inputs.forEach(function (inp) {
        if (byId[inp.prevTxid]) { adj[inp.prevTxid].push(t.txid); inDegree[t.txid]++; }
      });
    });
    var queue = [], order = [];
    txs.forEach(function (t) { if (inDegree[t.txid] === 0) queue.push(t.txid); });
    while (queue.length) {
      var id = queue.shift(); order.push(id);
      adj[id].forEach(function (n) { if (--inDegree[n] === 0) queue.push(n); });
    }
    if (order.length !== txs.length) throw new Error('cycle detected in tx graph');
    return order.map(function (id) { return byId[id]; }); // ancestors first
  }

  // ---- serialize BEEF ----------------------------------------------
  // input: { bumps: [bumpObj...], transactions: [{rawHex, inputs?, bumpIndex}] }
  function build(beef) {
    var ordered = topoSort(beef.transactions.map(function (t) {
      return { txid: t.txid || txidOf(fromHex(t.rawHex)), rawHex: t.rawHex,
               inputs: t.inputs || readRawTx(new Reader(fromHex(t.rawHex))).inputs,
               bumpIndex: (t.bumpIndex === undefined ? null : t.bumpIndex) };
    }));
    var w = new Writer();
    w.bytes(new Uint8Array(BEEF_VERSION));
    w.varInt(beef.bumps.length);
    beef.bumps.forEach(function (b) { w.hex(BUMP.toHex(b)); });
    w.varInt(ordered.length);
    ordered.forEach(function (t) {
      w.hex(t.rawHex);
      if (t.bumpIndex === null || t.bumpIndex === undefined) w.u8(0);
      else { w.u8(1); w.varInt(t.bumpIndex); }
    });
    return w.toHex();
  }

  // ---- Atomic BEEF wrap / unwrap -----------------------------------
  function wrapAtomic(beefHex, subjectTxidDisplay) {
    return toHex(new Uint8Array(ATOMIC_PREFIX)) + toHex(reverse(fromHex(subjectTxidDisplay))) + beefHex;
  }
  function isAtomic(hex) { return new Reader(fromHex(hex)).peekEq(ATOMIC_PREFIX); }

  // ---- self-test against the BRC-62 published example --------------
  var BRC62_HEX = '0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000';

  function selfTest() {
    var results = [], ok = true;
    function check(n, c) { results.push({ name: n, pass: !!c }); if (!c) ok = false; }

    var beef = parse(BRC62_HEX);
    check('parsed 1 BUMP', beef.bumps.length === 1);
    check('parsed 2 transactions', beef.transactions.length === 2);

    var t0 = beef.transactions[0], t1 = beef.transactions[1];
    check('tx0 has BUMP index 0', t0.bumpIndex === 0);
    check('tx1 has no BUMP', t1.bumpIndex === null);
    check('tx0 txid present in its BUMP level-0', beef.bumps[0].path[0].some(function (l) { return l.hash === t0.txid; }));
    check('tx1 spends tx0 (local parent link)', t1.inputs[0].prevTxid === t0.txid);

    // merkle root computes without throwing
    var rootRan = true; try { BUMP.merkleRoot(beef.bumps[0], t0.txid); } catch (e) { rootRan = false; }
    check('merkleRoot(tx0) computes', rootRan);

    // verify report: tx0 proven, tx1 unproven (correctly, since no BUMP)
    var rep = verifyMined(beef, function () { return true; });
    check('verify: exactly 1 proven tx', rep.proven.length === 1 && rep.proven[0].txid === t0.txid);
    check('verify: exactly 1 unproven tx', rep.unproven.length === 1 && rep.unproven[0] === t1.txid);

    // round-trip container: parse -> build -> identical hex
    check('BEEF round-trip byte-identical', build(beef) === BRC62_HEX.toLowerCase());

    // Atomic wrap/unwrap
    var atomicHex = wrapAtomic(BRC62_HEX, t1.txid);
    check('isAtomic(wrapped) === true', isAtomic(atomicHex) === true);
    check('isAtomic(plain) === false', isAtomic(BRC62_HEX) === false);
    var reparsed = parse(atomicHex);
    check('atomic subject txid preserved', reparsed.atomicSubject === t1.txid);
    check('atomic body still parses to 2 txs', reparsed.transactions.length === 2);

    return { passed: ok, results: results };
  }

  return {
    parse: parse,
    build: build,
    verifyMined: verifyMined,
    topoSort: topoSort,
    wrapAtomic: wrapAtomic,
    isAtomic: isAtomic,
    txidOf: function (rawHex) { return txidOf(fromHex(rawHex)); },
    selfTest: selfTest,
    VECTOR: { hex: BRC62_HEX }
  };
});

if (typeof module === 'object' && module.exports && require.main === module) {
  var out = module.exports.selfTest();
  out.results.forEach(function (r) { console.log((r.pass ? 'PASS ' : 'FAIL ') + r.name); });
  console.log('\n' + (out.passed ? 'ALL PASSED' : 'FAILURES PRESENT'));
  process.exit(out.passed ? 0 : 1);
}
