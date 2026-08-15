'use strict';
const fs = require('fs');
const vm = require('vm');
const crypto = require('crypto');

// ---- load a stack (crypto.js, encoding.js, headers.js) into one context -----
function loadStack() {
  const ctx = {};
  ctx.global = ctx;                 // libs attach exports here
  ctx.performance = { now: () => 0 };
  ctx.TextEncoder = TextEncoder;
  ctx.Date = Date;
  ctx.console = console;
  vm.createContext(ctx);
  for (const f of ['crypto.js', 'encoding.js', 'headers.js']) {
    vm.runInContext(fs.readFileSync('/home/claude/' + f, 'utf8'), ctx);
  }
  return ctx;
}

// ---- extract the audit functions from an explorer.html and eval into ctx ----
function loadAudit(ctx, htmlPath) {
  const html = fs.readFileSync(htmlPath, 'utf8');
  const start = html.indexOf('function sha256Single');
  const endMark = "return 'Corrupted branch, wrong sibling, or mismatched header';\n    }";
  const end = html.indexOf(endMark) + endMark.length;
  if (start < 0 || end < endMark.length) throw new Error('could not slice audit fns from ' + htmlPath);
  vm.runInContext(html.slice(start, end), ctx);
  return ctx.verify;
}

const ctxOld = loadStack(); const verifyOld = loadAudit(ctxOld, '/mnt/user-data/uploads/explorer.html');
const ctxNew = loadStack(); const verifyNew = loadAudit(ctxNew, '/home/claude/explorer.html');

// ---- the real envelope from the audit report the user showed -----------------
const realEnvelope = {
  txid: '3d26b16f881509eecc3a9674a47df683dba09d4a1b6a1735acffca92b91a51b7',
  blockHeader: '00c0b92206a9f8d17f468d91e26997117579d1a7e765b023c71d8d090000000000000000872a6c97d53151b4551a7f7fcf995290ff3a14b4931928d950acaffcaeed5732196e556a147626185aacdce4',
  proof: [
    { hash: '7958138dd587114db9c1554e1cad1c8b49f80e0027aa73e011e279598972b71a', pos: 'L' },
    { hash: '525dad7403cea93e5e859d4e208f332bdc5ca977cf0fe5c6686611126b142f68', pos: 'R' },
    { hash: '7c25e9c1bee21017f4725622f3028f47127859e26f2d9e2f5b7a281be8216567', pos: 'L' },
    { hash: '10481e6ec430ea4e9966748a74a90cfe080c40206351b53624706835b728859f', pos: 'R' },
    { hash: '757aa872fc285b60211bcd7f25e6bc4dea60371205ba793ca29b34e567d3141a', pos: 'R' },
    { hash: 'fec258f0e81278eafe55f0ebb81c440436eb0b4767a0bfb36d667a1062f25bb3', pos: 'L' },
    { hash: '5137a0fc06ff26db3430a635b8d24683df95b05d1aa24012ff04557c674b08a9', pos: 'R' },
    { hash: '1149016cd3f7a8061f425cbc4f46339f01d6b7d7e339b15f2c1c2d0e8548ecfc', pos: 'R' },
    { hash: '1e3ba5e2d9db238835871e7978e1d41e16076fb1e7468bb5e656ecb2c3e901d0', pos: 'L' },
    { hash: '4480947581c57dca2c7310a78e1d500796500b83f4720fd0ac05eb0c38cb617f', pos: 'R' },
    { hash: '7c5b77eb4dac2941e2872abf926a8840d15e272651d3624cedec2dc227c97b02', pos: 'R' },
    { hash: '75c6ab95a032562bb807724ed41dcfa55d5d1e8bd237ed74db1e96ea1314c8a3', pos: 'R' },
    { hash: 'd6161d0ff124632ce64e70131fc31c690889b594bb32cce17303ff5898869db9', pos: 'L' },
    { hash: 'ac376a589c988cf5f3f53c6b669beb7c0a91fc1fdb499acc46aefed198c3483b', pos: 'R' },
    { hash: 'bc72b13e4b06d2e8ecdffcf88dbe8ab4f677b4baf43e1863cf1b9929fb7e55bd', pos: 'R' },
    { hash: '8992360d30232064fcce55f20a498d6c1fb351ebc5efe9433039e14c9ae8957c', pos: 'L' },
    { hash: '29e10c8a786eab3b8f5823b81f92774626252d2ec72d6fcd3c674689ab5e09ef', pos: 'R' }
  ],
  blockHeight: 935023
};

let pass = 0, fail = 0; const fails = [];
const ok = (c, m) => { c ? pass++ : (fail++, fails.push(m)); };

// ===========================================================================
// 1. Valid input: new audit still VALID, root reproduces, identifiers UNCHANGED
// ===========================================================================
const ro = verifyOld(realEnvelope);
const rn = verifyNew(realEnvelope);
ok(rn.result.valid === true, 'real envelope still VALID after hardening');
const rootStep = rn.steps.find(s => s.type === 'root');
ok(rootStep && rootStep.computedRoot === '872a6c97d53151b4551a7f7fcf995290ff3a14b4931928d950acaffcaeed5732',
  'computed merkle root reproduces 872a6c97… (internal order, as report prints)');
ok(ro.hashes.inputFingerprint === rn.hashes.inputFingerprint, 'inputFingerprint UNCHANGED old vs new');
ok(ro.hashes.verificationHash === rn.hashes.verificationHash, 'verificationHash UNCHANGED old vs new');
ok(ro.hashes.replayId === rn.hashes.replayId, 'replayId UNCHANGED old vs new');

// ===========================================================================
// 2. Reproduce the EXACT identifiers from the user's report
// ===========================================================================
ok(rn.hashes.inputFingerprint === 'f79fee9e3a15ff318e0ec8a12d7192b5', 'inputFingerprint reproduces report (f79fee9e…)');
ok(rn.hashes.verificationHash === 'c300073d26e61ee874692b21fdf25eb56561682e59019fc2eb5cf593bdbab23f', 'verificationHash reproduces report (c300073d…)');
ok(rn.hashes.replayId === 'C300073D26E61EE8', 'replayId reproduces report (C300073D26E61EE8)');

// ===========================================================================
// 3. THE FIX: a duplicate-sibling proof that still hits the root.
//    Old audit reports VALID (bug); new audit must FAIL closed.
// ===========================================================================
const sha256d = (buf) => crypto.createHash('sha256').update(crypto.createHash('sha256').update(buf).digest()).digest();
const rev = (h) => Buffer.from(h, 'hex').reverse();

const T = '11'.repeat(32);                 // txid (display)
const X = 'aa'.repeat(32);                 // duplicated sibling
// compute the internal root this 2-step (R,R) proof yields
let cur = rev(T);
cur = sha256d(Buffer.concat([cur, Buffer.from(X, 'hex')]));  // level 0, pos R
cur = sha256d(Buffer.concat([cur, Buffer.from(X, 'hex')]));  // level 1, pos R (duplicate X)
const rootInternal = Buffer.from(cur).toString('hex');       // header merkle field (natural order)

// craft an 80-byte header with easy difficulty, merkle=rootInternal, grind nonce to pass PoW
function buildHeader(nonce) {
  const version = '01000000';
  const prev = '00'.repeat(32);
  const bitsLE = 'ffff7f20';               // nBits 0x207fffff (very easy)
  const timeLE = Buffer.alloc(4); timeLE.writeUInt32LE(Math.floor(Date.now() / 1000));
  const nonceLE = Buffer.alloc(4); nonceLE.writeUInt32LE(nonce >>> 0);
  return version + prev + rootInternal + timeLE.toString('hex') + bitsLE + nonceLE.toString('hex');
}
let cveHeader = null;
for (let n = 0; n < 500000; n++) {
  const h = buildHeader(n);
  if (ctxNew.verifyPoW(h)) { cveHeader = h; break; }
}
ok(cveHeader !== null, 'crafted a PoW-valid easy-difficulty header for the CVE test');

const cveEnvelope = { txid: T, blockHeader: cveHeader, proof: [{ hash: X, pos: 'R' }, { hash: X, pos: 'R' }], blockHeight: 999999 };
const cveOld = verifyOld(cveEnvelope);
const cveNew = verifyNew(cveEnvelope);
ok(cveOld.result.valid === true, 'OLD audit reports the duplicate-sibling proof as VALID (the bug)');
ok(cveNew.result.valid === false, 'NEW audit FAILS the duplicate-sibling proof (fixed, closes CVE-2012-2459 gap)');
ok(cveNew.checks.find(c => c.name.startsWith('Structure')).pass === false, 'NEW audit flags Structure check as failed');
ok(cveNew.checks.find(c => c.name.startsWith('Proof safety')).pass === false, 'NEW audit flags Proof-safety check as failed');

// ===========================================================================
// 4. Difficulty floor is surfaced: real block PASSES floor, easy header BELOW floor
// ===========================================================================
ok(rn.assurance.difficultyFloor.valid === true, 'real block passes difficulty floor');
ok(cveNew.assurance.difficultyFloor.valid === false, 'easy-difficulty header flagged BELOW floor');
ok(rn.assurance.chainInclusion.verified === false, 'chain-inclusion honestly reported as not verified');

// ===========================================================================
// 5. Tampered sibling: both old and new FAIL (root mismatch), no regression
// ===========================================================================
const tampered = JSON.parse(JSON.stringify(realEnvelope));
tampered.proof[3].hash = 'ff' + tampered.proof[3].hash.slice(2);
ok(verifyNew(tampered).result.valid === false, 'tampered sibling still FAILS');

console.log('----------------------------------------');
console.log(`PASSED: ${pass}   FAILED: ${fail}`);
if (fail) fails.forEach(f => console.log('  - ' + f));
process.exit(fail ? 1 : 0);
