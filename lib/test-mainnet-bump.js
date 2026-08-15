'use strict';
const fs = require('fs');
const vm = require('vm');
const crypto = require('crypto');

const ctx = {}; ctx.global = ctx; ctx.console = console;
vm.createContext(ctx);
for (const f of ['crypto.js', 'encoding.js', 'headers.js', 'bump.js'])
  vm.runInContext(fs.readFileSync('/home/claude/' + f, 'utf8'), ctx);
const BUMP = ctx.BUMP, reverseHex = ctx.reverseHex;

// Real Block 170 data
const coinbase = 'b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082'; // v3.txid (display)
const payment  = 'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16'; // sibling (display)
const expectedRoot = '7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff';
// legacy proof stores sibling in INTERNAL byte order, coinbase is left so sibling is 'R'
const merkleProof = [{ hash: reverseHex(payment), pos: 'R' }];

// exact copy of the function added to tests-mainnet.html
function bumpFromLegacyProof(txid, proof, blockHeight) {
  let index = 0;
  for (let h = 0; h < proof.length; h++) if (proof[h].pos === 'L') index |= (1 << h);
  const path = [];
  const lvl0 = [{ offset: index, txid: true, hash: txid.toLowerCase() }];
  const sib0 = index ^ 1;
  lvl0.push(proof[0].hash === '*' ? { offset: sib0, duplicate: true }
    : { offset: sib0, hash: reverseHex(proof[0].hash).toLowerCase() });
  lvl0.sort((a, b) => a.offset - b.offset);
  path.push(lvl0);
  for (let h = 1; h < proof.length; h++) {
    const sib = (index >> h) ^ 1;
    path.push([ proof[h].hash === '*' ? { offset: sib, duplicate: true }
      : { offset: sib, hash: reverseHex(proof[h].hash).toLowerCase() } ]);
  }
  return { blockHeight: blockHeight || 0, path: path };
}

let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log((c ? 'PASS ' : 'FAIL ') + m); };

// independent oracle: sha256d(coinbase_internal || payment_internal), reversed
const sha256d = b => crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest();
const rev = h => Buffer.from(h, 'hex').reverse();
const oracleRoot = Buffer.from(sha256d(Buffer.concat([rev(coinbase), rev(payment)]))).reverse().toString('hex');
ok(oracleRoot === expectedRoot, 'independent oracle reproduces 7dac2c56… (sanity)');

const bump = bumpFromLegacyProof(coinbase, merkleProof, 170);
const root = BUMP.merkleRoot(bump, coinbase.toLowerCase());
ok(root.toLowerCase() === expectedRoot.toLowerCase(), 'BUMP reconstructs real mainnet root 7dac2c56…');
ok(BUMP.toHex(BUMP.fromHex(BUMP.toHex(bump))) === BUMP.toHex(bump), 'BUMP serializer round-trips');

console.log('\n----------------------------------------');
console.log('PASSED: ' + pass + '   FAILED: ' + fail);
process.exit(fail ? 1 : 0);
