/*
 * bump.js — BSV Unified Merkle Path (BUMP, BRC-74) reader / writer / root calculator.
 *
 * Pure vanilla JavaScript. No dependencies, no imports, no CDN. Runs in a browser
 * (attaches to window.BUMP) or in Node (module.exports). Written to drop straight
 * into verifier.html for the hybrid path: compute the merkle root from a BUMP, then
 * check it against the block-header root you already carry in the envelope.
 *
 * Spec: https://bsv.brc.dev/transactions/0074
 *
 * BYTE ORDER NOTE (read this before integrating):
 *   All hashes/txids in this module — inputs and the returned root — are in the
 *   DISPLAY convention (reversed byte order, the way a txid is printed). A raw block
 *   header's merkle-root field (bytes 36..68) is in NATURAL (internal) byte order.
 *   So to compare the returned root against a header field, reverse one of them.
 *   Helpers reverseHex() is exported for exactly this.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.BUMP = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ------------------------------------------------------------------
  // SHA-256 (pure JS, operates on Uint8Array -> Uint8Array(32))
  // ------------------------------------------------------------------
  var K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256(msg) {
    var h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,
        h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;

    var l = msg.length;
    var bitLen = l * 8;
    // padded length: message + 0x80 + zeros + 8-byte length, multiple of 64
    var padded = new Uint8Array(((l + 8) >> 6 << 6) + 64);
    padded.set(msg, 0);
    padded[l] = 0x80;
    // 64-bit big-endian length (high 32 bits assumed 0 for our small inputs)
    var hi = Math.floor(bitLen / 0x100000000);
    var lo = bitLen >>> 0;
    var p = padded.length;
    padded[p-8]=(hi>>>24)&0xff; padded[p-7]=(hi>>>16)&0xff; padded[p-6]=(hi>>>8)&0xff; padded[p-5]=hi&0xff;
    padded[p-4]=(lo>>>24)&0xff; padded[p-3]=(lo>>>16)&0xff; padded[p-2]=(lo>>>8)&0xff; padded[p-1]=lo&0xff;

    var w = new Uint32Array(64);
    for (var off = 0; off < padded.length; off += 64) {
      for (var i = 0; i < 16; i++) {
        w[i] = (padded[off+i*4]<<24)|(padded[off+i*4+1]<<16)|(padded[off+i*4+2]<<8)|(padded[off+i*4+3]);
      }
      for (i = 16; i < 64; i++) {
        var s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>>3);
        var s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2]>>>10);
        w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
      }
      var a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,hh=h7;
      for (i = 0; i < 64; i++) {
        var S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + K[i] + w[i]) | 0;
        var S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) | 0;
        hh=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
      }
      h0=(h0+a)|0; h1=(h1+b)|0; h2=(h2+c)|0; h3=(h3+d)|0;
      h4=(h4+e)|0; h5=(h5+f)|0; h6=(h6+g)|0; h7=(h7+hh)|0;
    }
    var out = new Uint8Array(32);
    var hs = [h0,h1,h2,h3,h4,h5,h6,h7];
    for (i = 0; i < 8; i++) {
      out[i*4]  =(hs[i]>>>24)&0xff; out[i*4+1]=(hs[i]>>>16)&0xff;
      out[i*4+2]=(hs[i]>>>8)&0xff;  out[i*4+3]=hs[i]&0xff;
    }
    return out;
  }

  // Default double-SHA256; overridable via configure() so you can reuse
  // verifier.html's existing crypto instead of shipping two copies.
  var _sha256d = function (u8) { return sha256(sha256(u8)); };

  // ------------------------------------------------------------------
  // hex helpers
  // ------------------------------------------------------------------
  function fromHex(hex) {
    // Strict: reject odd length / non-hex rather than coercing NaN -> 0 (audit item 9).
    if (typeof hex !== 'string' || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
      throw new Error('BUMP: invalid hex input');
    }
    var a = new Uint8Array(hex.length / 2);
    for (var i = 0; i < a.length; i++) a[i] = parseInt(hex.substr(i*2, 2), 16);
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
  function reverseHex(hex) { return toHex(reverse(fromHex(hex))); }
  var hexRevToBuf = function (hex) { return reverse(fromHex(hex)); };
  var bufRevToHex = function (u8) { return toHex(reverse(u8)); };

  // hash of a display-hex string (matches BRC-74 reference `hash()`):
  // reverse whole concat to natural order, double-sha256, reverse back to display.
  function hashHex(displayHex) { return bufRevToHex(_sha256d(hexRevToBuf(displayHex))); }

  // ------------------------------------------------------------------
  // VarInt-aware byte reader / writer
  // ------------------------------------------------------------------
  function Reader(u8) { this.buf = u8; this.pos = 0; }
  // Bounds-checked reads (audit item 9). Without these, a truncated stream or a
  // bad VarInt silently under-parses (u8() past end -> undefined, bytes() past
  // end -> short subarray) and yields a "valid" object rather than rejecting.
  Reader.prototype.u8 = function () {
    if (this.pos >= this.buf.length) throw new Error('BUMP: unexpected end of stream');
    return this.buf[this.pos++];
  };
  Reader.prototype.bytes = function (n) {
    if (this.pos + n > this.buf.length) throw new Error('BUMP: read past end of stream');
    var b = this.buf.subarray(this.pos, this.pos + n); this.pos += n; return b;
  };
  Reader.prototype.varInt = function () {
    var f = this.u8();
    if (f < 0xfd) return f;
    if (f === 0xfd) { var a=this.u8(),b=this.u8(); return a | (b<<8); }
    if (f === 0xfe) { var c=this.bytes(4); return c[0] | (c[1]<<8) | (c[2]<<16) | (c[3]*0x1000000); }
    // 0xff: 8-byte LE. Safe for block heights / offsets (well under 2^53).
    var d = this.bytes(8), lo=0, hi=0;
    lo = d[0] | (d[1]<<8) | (d[2]<<16) | (d[3]*0x1000000);
    hi = d[4] | (d[5]<<8) | (d[6]<<16) | (d[7]*0x1000000);
    return hi * 0x100000000 + lo;
  };

  function Writer() { this.parts = []; }
  Writer.prototype.u8 = function (n) { this.parts.push(new Uint8Array([n & 0xff])); return this; };
  Writer.prototype.bytes = function (u8) { this.parts.push(u8); return this; };
  Writer.prototype.varInt = function (n) {
    if (n < 0xfd) return this.u8(n);
    if (n <= 0xffff) return this.bytes(new Uint8Array([0xfd, n & 0xff, (n>>>8)&0xff]));
    if (n <= 0xffffffff) return this.bytes(new Uint8Array([0xfe, n&0xff, (n>>>8)&0xff, (n>>>16)&0xff, (n>>>24)&0xff]));
    var lo = n >>> 0, hi = Math.floor(n / 0x100000000);
    return this.bytes(new Uint8Array([0xff, lo&0xff,(lo>>>8)&0xff,(lo>>>16)&0xff,(lo>>>24)&0xff,
                                            hi&0xff,(hi>>>8)&0xff,(hi>>>16)&0xff,(hi>>>24)&0xff]));
  };
  Writer.prototype.toHex = function () {
    var len = 0, i; for (i=0;i<this.parts.length;i++) len += this.parts[i].length;
    var out = new Uint8Array(len), o = 0;
    for (i=0;i<this.parts.length;i++){ out.set(this.parts[i], o); o += this.parts[i].length; }
    return toHex(out);
  };

  // ------------------------------------------------------------------
  // BUMP parse / serialize
  // ------------------------------------------------------------------
  var DUPLICATE = 1, CLIENT_TXID = 2;

  function fromHexBUMP(hex) {
    var r = new Reader(fromHex(hex));
    var blockHeight = r.varInt();
    var treeHeight = r.u8();
    var path = [];
    for (var lvl = 0; lvl < treeHeight; lvl++) {
      var n = r.varInt(), leaves = [];
      for (var i = 0; i < n; i++) {
        var offset = r.varInt();
        var flags = r.u8();
        var leaf = { offset: offset };
        if (flags & DUPLICATE) {
          leaf.duplicate = true;
        } else {
          if (flags & CLIENT_TXID) leaf.txid = true;
          leaf.hash = toHex(reverse(r.bytes(32))); // store as display hex
        }
        leaves.push(leaf);
      }
      leaves.sort(function (a, b) { return a.offset - b.offset; });
      path.push(leaves);
    }
    // Reject trailing garbage: a well-formed BUMP consumes its buffer exactly.
    if (r.pos !== r.buf.length) throw new Error('BUMP: ' + (r.buf.length - r.pos) + ' trailing byte(s) after path');
    return { blockHeight: blockHeight, path: path };
  }

  function toHexBUMP(bump) {
    var w = new Writer();
    w.varInt(bump.blockHeight);
    w.u8(bump.path.length);
    for (var lvl = 0; lvl < bump.path.length; lvl++) {
      var leaves = bump.path[lvl];
      w.varInt(leaves.length);
      for (var i = 0; i < leaves.length; i++) {
        var leaf = leaves[i];
        w.varInt(leaf.offset);
        var flags = 0;
        if (leaf.duplicate) flags |= DUPLICATE;
        if (leaf.txid) flags |= CLIENT_TXID;
        w.u8(flags);
        if (!(flags & DUPLICATE)) w.bytes(hexRevToBuf(leaf.hash));
      }
    }
    return w.toHex();
  }

  // ------------------------------------------------------------------
  // Merkle root from a BUMP for a given (display-hex) txid.
  // Returns the root in display hex. Throws if the txid isn't covered.
  // ------------------------------------------------------------------
  function merkleRoot(bump, txid) {
    var level0 = bump.path[0];
    var start = null;
    for (var i = 0; i < level0.length; i++) if (level0[i].hash === txid) { start = level0[i]; break; }
    if (start === null) throw new Error('BUMP does not contain txid ' + txid);
    var index = start.offset;
    var working = txid;
    for (var height = 0; height < bump.path.length; height++) {
      var siblingOffset = (index >> height) ^ 1;
      var leaf = null, lvl = bump.path[height];
      for (var j = 0; j < lvl.length; j++) if (lvl[j].offset === siblingOffset) { leaf = lvl[j]; break; }
      if (leaf === null) throw new Error('BUMP missing sibling at height ' + height);
      if (leaf.duplicate) working = hashHex(working + working);
      else if (siblingOffset & 1) working = hashHex(leaf.hash + working); // sibling on the right
      else working = hashHex(working + leaf.hash);                        // sibling on the left
    }
    return working;
  }

  // ------------------------------------------------------------------
  // Self-test against the BRC-74 published vector.
  // Returns { passed: bool, results: [...] }; also throws on hard failure.
  // ------------------------------------------------------------------
  var VECTOR_HEX = 'fe8a6a0c000c04fde80b0011774f01d26412f0d16ea3f0447be0b5ebec67b0782e321a7a01cbdf7f734e30fde90b02004e53753e3fe4667073063a17987292cfdea278824e9888e52180581d7188d8fdea0b025e441996fc53f0191d649e68a200e752fb5f39e0d5617083408fa179ddc5c998fdeb0b0102fdf405000671394f72237d08a4277f4435e5b6edf7adc272f25effef27cdfe805ce71a81fdf50500262bccabec6c4af3ed00cc7a7414edea9c5efa92fb8623dd6160a001450a528201fdfb020101fd7c010093b3efca9b77ddec914f8effac691ecb54e2c81d0ab81cbc4c4b93befe418e8501bf01015e005881826eb6973c54003a02118fe270f03d46d02681c8bc71cd44c613e86302f8012e00e07a2bb8bb75e5accff266022e1e5e6e7b4d6d943a04faadcf2ab4a22f796ff30116008120cafa17309c0bb0e0ffce835286b3a2dcae48e4497ae2d2b7ced4f051507d010a00502e59ac92f46543c23006bff855d96f5e648043f0fb87a7a5949e6a9bebae430104001ccd9f8f64f4d0489b30cc815351cf425e0e78ad79a589350e4341ac165dbe45010301010000af8764ce7e1cc132ab5ed2229a005c87201c9a5ee15c0f91dd53eff31ab30cd4';
  var VECTOR_ROOT = '57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4';
  var VECTOR_TXIDS = [
    '304e737fdfcb017a1a322e78b067ecebb5e07b44f0a36ed1f01264d2014f7711',
    'd888711d588021e588984e8278a2decf927298173a06737066e43f3e75534e00',
    '98c9c5dd79a18f40837061d5e0395ffb52e700a2689e641d19f053fc9619445e'
  ];

  function selfTest() {
    var results = [], ok = true;
    function check(name, cond) { results.push({ name: name, pass: !!cond }); if (!cond) ok = false; }

    // 0. sanity: sha256("abc")
    check('sha256("abc")',
      toHex(sha256(new Uint8Array([0x61,0x62,0x63]))) ===
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

    var bump = fromHexBUMP(VECTOR_HEX);
    check('blockHeight === 813706', bump.blockHeight === 813706);
    check('treeHeight === 12', bump.path.length === 12);

    for (var i = 0; i < VECTOR_TXIDS.length; i++) {
      check('root from txid #' + (i+1), merkleRoot(bump, VECTOR_TXIDS[i]) === VECTOR_ROOT);
    }

    check('round-trip hex === original', toHexBUMP(bump) === VECTOR_HEX.toLowerCase());

    return { passed: ok, results: results };
  }

  return {
    fromHex: fromHexBUMP,
    toHex: toHexBUMP,
    merkleRoot: merkleRoot,
    selfTest: selfTest,
    reverseHex: reverseHex,       // for header-field comparison (display <-> natural)
    sha256: sha256,
    configure: function (opts) { if (opts && typeof opts.sha256d === 'function') _sha256d = opts.sha256d; },
    VECTOR: { hex: VECTOR_HEX, root: VECTOR_ROOT, txids: VECTOR_TXIDS }
  };
});

// Auto-run the self-test when executed directly under Node.
if (typeof module === 'object' && module.exports && require.main === module) {
  var out = module.exports.selfTest();
  out.results.forEach(function (r) { console.log((r.pass ? 'PASS ' : 'FAIL ') + r.name); });
  console.log('\n' + (out.passed ? 'ALL PASSED' : 'FAILURES PRESENT'));
  process.exit(out.passed ? 0 : 1);
}
