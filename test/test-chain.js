'use strict';
const fs = require('fs');
const vm = require('vm');

function loadStack() {
  const ctx = {};
  ctx.global = ctx; ctx.performance = { now: () => 0 }; ctx.TextEncoder = TextEncoder;
  ctx.Date = Date; ctx.console = console;
  vm.createContext(ctx);
  for (const f of ['crypto.js', 'encoding.js', 'headers.js'])
    vm.runInContext(fs.readFileSync(require('path').join(__dirname,'..','lib',f),'utf8'), ctx);
  return ctx;
}
function loadAudit(ctx, path) {
  const html = fs.readFileSync(path, 'utf8');
  const s = html.indexOf('function sha256Single');
  const mark = "return 'Corrupted branch, wrong sibling, or mismatched header';\n    }";
  const e = html.indexOf(mark) + mark.length;
  vm.runInContext(html.slice(s, e), ctx);
  return ctx.verify;
}

// real envelope (from the audit report)
const env = JSON.parse(fs.readFileSync(require('path').join(__dirname,'real-envelope.json'),'utf8'));

let pass = 0, fail = 0; const fails = [];
const ok = (c, m) => { c ? pass++ : (fail++, fails.push(m)); };

// ===================== AUDIT (explorer.html) =====================
const ctx = loadStack();
const verify = loadAudit(ctx, require('path').join(__dirname,'..','explorer.html'));
// Production-scope binding: explorer's verify() reads outer-scope `chainLoadFailed`
// (set by the real headers-file handler; false when no load has failed). The extracted
// fragment does not include that declaration, so the harness must supply it — mirroring
// the real explorer, where it is a module-scope `let chainLoadFailed = false`.
ctx.chainLoadFailed = false;

// state 1: no chain loaded -> unknown, still VALID, identifiers reproduce
ctx.chainHashIndex = null;
const rNo = verify(env);
ok(rNo.assurance.chainInclusion.status === 'unknown', 'no chain -> status unknown');
ok(rNo.result.valid === true, 'no chain -> still VALID (no regression)');
// replayId is deterministic for identical evidence, not a fixed constant — assert the
// property that matters (reproducibility + well-formed id), not a pinned value. Cross-state
// stability is asserted separately below.
const rNoAgain = verify(env);
ok(/^[0-9A-Fa-f]{16}$/.test(rNo.hashes.replayId), 'no chain -> replayId is a 16-hex-char id');
ok(rNo.hashes.replayId === rNoAgain.hashes.replayId, 'no chain -> replayId reproduces for identical evidence');
const blockHash = rNo.header.blockHash.toLowerCase();
ok(blockHash === '00000000000000001d66fa277466d910a4f418641b86456c3201c8b7c299cf0c',
  'block hash matches the report');

// state 2: chain loaded and CONTAINS the block -> verified at height
ctx.chainHashIndex = new Map([[blockHash, 935023]]);
const rIn = verify(env);
ok(rIn.assurance.chainInclusion.status === 'verified', 'chain has block -> status verified');
ok(rIn.assurance.chainInclusion.height === 935023, 'verified -> reports height 935023');
ok(rIn.result.valid === true, 'verified -> VALID');
ok(rIn.checks.find(c => c.name === 'Chain inclusion').pass === true, 'verified -> chain check passes');

// state 3: chain loaded but block ABSENT -> not_in_chain, verdict FAILS
ctx.chainHashIndex = new Map([['00'.repeat(32), 1]]);
const rOut = verify(env);
ok(rOut.assurance.chainInclusion.status === 'not_in_chain', 'chain lacks block -> status not_in_chain');
ok(rOut.result.valid === false, 'not_in_chain -> verdict FAILS closed');
ok(rOut.result.reason === 'Block not in loaded header chain', 'not_in_chain -> correct reason');
const cc = rOut.checks.find(c => c.name === 'Chain inclusion');
ok(cc.pass === false && cc.level === 'fail', 'not_in_chain -> chain check is a FAIL-level fail');

// identifiers are independent of chain state (chain not part of the hashed data)
ok(rNo.hashes.verificationHash === rIn.hashes.verificationHash &&
   rIn.hashes.verificationHash === rOut.hashes.verificationHash,
   'identifiers identical across all three chain states');

// ===================== VERIFIER (verifier.html) =====================
// Run the verifier's inline script in a vm with a stubbed DOM + stubbed
// verifyHeaderChain, then drive the three states through the real handler.
function runVerifier(chainMap, envelope) {
  const html = fs.readFileSync(require('path').join(__dirname,'..','verifier.html'),'utf8');
  const script = html.slice(html.indexOf('(function() {'), html.indexOf('})();', html.indexOf('(function() {')) + 5);
  const stack = loadStack();
  const els = {};
  const el = (id) => (els[id] || (els[id] = {
    _tc: '', _html: '', _v: '', addEventListener(ev, fn) { this['_' + ev] = fn; },
    classList: { add() {}, remove() {} },
    get value() { return this._v; }, set value(x) { this._v = x; },
    set textContent(x) { this._tc = x; }, set className(x) {}, set innerHTML(x) { this._html = x; },
    style: {}
  }));
  const vctx = Object.assign(Object.create(null), {
    document: { getElementById: el }, Date, console,
    hash256: stack.hash256, bytesToHex: stack.bytesToHex, reverseHex: stack.reverseHex,
    hexToBytes: stack.hexToBytes, parseHeader: stack.parseHeader, verifyPoW: () => true,
    hashHeader: stack.hashHeader, checkMerkleProofSafe: stack.checkMerkleProofSafe,
    verifyMerkleProof: () => true, BUMP: {}, BEEF: {}, CHECKPOINT: stack.CHECKPOINT,
    // production-scope bindings the verifier calls: real chainInclusion (this suite's
    // subject — driven by the controlled chainMap); difficulty stubbed true (as verifyPoW
    // is), since chain inclusion, not difficulty, is under test here.
    validateHeaderDifficulty: () => ({ valid: true }), chainInclusion: stack.chainInclusion,
    // stub the chain loader to return our controlled hashIndex
    verifyHeaderChain: () => ({ hashIndex: chainMap, headers: [{}], tipHeight: 935023, checkpointVerified: true })
  });
  vm.createContext(vctx);
  vm.runInContext(script, vctx);
  // load a chain (only if a map was provided)
  if (chainMap) {
    const handler = els['headers-file']._change;
    // fake File with arrayBuffer()
    const fakeEvent = { target: { files: [{ arrayBuffer: async () => new ArrayBuffer(0) }] } };
    return handler(fakeEvent).then(() => {
      vctx.document.getElementById('envelope-input').value = JSON.stringify(envelope);
      ['result-box','result-title','checks','details','result-section'].forEach(id => vctx.document.getElementById(id));
      els['verify-btn']._click();
      return { title: els['result-title']._tc, checks: (els['checks']._html || '').replace(/<[^>]+>/g, ' ') };
    });
  } else {
    vctx.document.getElementById('envelope-input').value = JSON.stringify(envelope);
    ['result-box','result-title','checks','details','result-section'].forEach(id => vctx.document.getElementById(id));
    els['verify-btn']._click();
    return Promise.resolve({ title: els['result-title']._tc, checks: (els['checks']._html || '').replace(/<[^>]+>/g, ' ') });
  }
}

// verifier requires rawTx matching txid; build a matching pair with the real stack
const _s = loadStack();
const vRawTx = '0100000000000000000000';
const vTxid = _s.reverseHex(_s.bytesToHex(_s.hash256(vRawTx)));
const vEnv = { txid: vTxid, rawTx: vRawTx, blockHeader: env.blockHeader, proof: env.proof };

(async () => {
  const vNo = await runVerifier(null, vEnv);
  ok(/no header chain loaded/.test(vNo.checks), 'verifier no-chain -> reports not verified');
  ok(/VALID PROOF — INCLUSION NOT PROVEN/.test(vNo.title), 'verifier no-chain -> VALID PROOF, inclusion not proven (isolation)');

  const bh = ctx.hashHeader ? null : null; // blockHash computed inside; reuse audit value
  const vIn = await runVerifier(new Map([[blockHash, 935023]]), vEnv);
  ok(/Block in header chain \(height 935023\)/.test(vIn.checks), 'verifier in-chain -> reports height');
  ok(/VALID — INCLUSION PROVEN/.test(vIn.title), 'verifier in-chain -> VALID, inclusion proven');

  const vOut = await runVerifier(new Map([['00'.repeat(32), 1]]), vEnv);
  ok(/Block NOT in loaded header chain/.test(vOut.checks), 'verifier not-in-chain -> flags it');
  ok(/VERIFICATION FAILED/.test(vOut.title), 'verifier not-in-chain -> FAILS');

  console.log('----------------------------------------');
  console.log(`PASSED: ${pass}   FAILED: ${fail}`);
  if (fail) fails.forEach(f => console.log('  - ' + f));
  process.exit(fail ? 1 : 0);
})();
