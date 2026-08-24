'use strict';
/*
 * Conformance + differential harness.
 *   spec-expected outcome  <-  the semantic referee (frozen corpus, §G table)
 *   headers-node.verify()  ->  independent result B
 *   reference (explorer verify(), extracted)  ->  result A
 * Both A and B are compared against the SPEC, never A used as B's oracle.
 */
const fs = require('fs'), vm = require('vm'), crypto = require('crypto');
const HN = require('./verify.js');
const O = HN.OUTCOME;

// ---- load the reference explorer verify() in an isolated vm (outcome oracle) --------
function loadReference() {
  const ctx = {}; ctx.global = ctx; ctx.performance = { now: () => 0 };
  ctx.TextEncoder = TextEncoder; ctx.Date = Date; ctx.console = { log(){}, warn(){}, error(){} };
  vm.createContext(ctx);
  for (const f of ['crypto.js', 'encoding.js', 'headers.js'])
    vm.runInContext(fs.readFileSync(__dirname + '/../lib/' + f, 'utf8'), ctx);
  const html = fs.readFileSync(__dirname + '/../explorer.html', 'utf8');
  const s = html.indexOf('function sha256Single');
  const mark = "return 'Corrupted branch, wrong sibling, or mismatched header';\n    }";
  vm.runInContext(html.slice(s, html.indexOf(mark) + mark.length), ctx);
  return ctx;
}
const ref = loadReference();
function referenceOutcome(env, chainMap, stub) {
  ref.chainHashIndex = chainMap || null;
  ref.chainLoadFailed = false;
  const saved = {};
  if (stub) for (const k of Object.keys(stub)) { saved[k] = ref[k]; ref[k] = stub[k]; }
  let out;
  try { out = ref.verify(env).result.outcome; }
  catch (e) { out = 'THREW:' + e.message; }
  finally { for (const k of Object.keys(saved)) ref[k] = saved[k]; }
  return out;
}

// ---- corpus base: the real mainnet fixture (external data), valid bump + proof ------
const E = JSON.parse(fs.readFileSync(__dirname + '/../test/real-envelope.json', 'utf8'));
const clone = (o) => JSON.parse(JSON.stringify(o));
const hdr = HN.parseHeader(E.blockHeader);
const blockHash = HN.hashHeaderDisplay(E.blockHeader);
const chainHas = new Map([[blockHash.toLowerCase(), 935023]]);
const chainLacks = new Map([['00'.repeat(32), 1]]);

// sub-floor header: set nBits to 256x the checkpoint target — above the checkpoint*8 floor
// (so the floor rejects) yet still >= the real header's hash (so PoW passes). Same exponent+1,
// same mantissa => target * 256. Merkle-root bytes untouched, so the root still matches.
function subFloorHeader() {
  const b = Buffer.from(E.blockHeader, 'hex');
  b.writeUInt32LE(0x19227b71, 72); // 0x18227b71 (checkpoint) with exponent+1 => 256x target
  return b.toString('hex');
}
// wrong-header: flip a byte inside the merkle-root field -> root mismatch
function wrongRootHeader() {
  const b = Buffer.from(E.blockHeader, 'hex'); b[36] ^= 0xff; return b.toString('hex');
}

const cases = [
  { id: '1 valid isolation',     env: E,                                         chain: null,       spec: O.VERIFIED_ISOLATION },
  { id: '2 valid inclusion',     env: E,                                         chain: chainHas,   spec: O.VERIFIED },
  { id: '3 not in chain',        env: E,                                         chain: chainLacks, spec: O.FAILED },
  { id: '5 wrong header (root)', env: merge(E,{blockHeader: wrongRootHeader()}), chain: null,       spec: O.FAILED },
  { id: '8a malformed header',   env: merge(E,{blockHeader: '00'}),              chain: null,       spec: O.MALFORMED },
  { id: '8b empty header',       env: merge(E,{blockHeader: ''}),                chain: null,       spec: O.MALFORMED },
  { id: '8c missing header',     env: strip(E,'blockHeader'),                    chain: null,       spec: O.MALFORMED },
  { id: '9 malformed proof',     env: strip(merge(E,{proof:[{hash:'zz',pos:'L'}]}),'bump'), chain: null, spec: O.MALFORMED },
];
function merge(o, patch){ return Object.assign(clone(o), patch); }
function strip(o, k){ const c = clone(o); delete c[k]; return c; }

// ---- differential table -------------------------------------------------------------
function pad(s,n){ s=String(s); return s + ' '.repeat(Math.max(0,n-s.length)); }
console.log('CASE                         SPEC                 headers-node         reference            MATCH');
console.log('-'.repeat(104));
let hnMatch=0, refMatch=0, bothMatch=0, total=0;
const divergences=[];
for (const c of cases) {
  total++;
  // headers-node: explorer scope (does not bind rawTx) for a like-for-like outcome compare
  const hn = HN.verify(c.env, { chainHashIndex: c.chain, bindRawTx: false }).outcome;
  const rf = referenceOutcome(c.env, c.chain);
  const hnOk = hn === c.spec, rfOk = rf === c.spec;
  if (hnOk) hnMatch++; if (rfOk) refMatch++; if (hnOk && rfOk) bothMatch++;
  const m = (hn===rf) ? (hnOk?'both=spec':'agree≠spec') : 'DIVERGE';
  if (!hnOk || !rfOk || hn!==rf) divergences.push({c,hn,rf});
  console.log(pad(c.id,28), pad(c.spec,20), pad(hn,20), pad(rf,20), m);
}

// ---- evaluation-failure axis (INDETERMINATE) — stub a dependency to throw -----------
console.log('\n--- evaluation-failure axis ---');
const hnEval = HN.verify(E, { chainHashIndex: null, bindRawTx: false,
  // inject an evaluation failure through a poisoned difficulty check by monkeypatching:
});
// headers-node: simulate undefined dependency via a wrapper that throws
(function(){
  const realVerify = HN.verify;
  // craft an envelope whose difficulty check throws by temporarily breaking targetFromBits?
  // simplest: call classifyOutcome path directly is internal; instead assert reference + hn
  // both map a thrown dependency to INDETERMINATE using their own boundaries.
  const rf = referenceOutcome(E, null, { validateHeaderDifficulty: () => { throw new ReferenceError('boom'); } });
  console.log(pad('11 dep throws (reference)',28), pad(O.INDETERMINATE,20), pad('n/a',20), pad(rf,20), rf===O.INDETERMINATE?'ref=spec':'DIVERGE');
  if (rf!==O.INDETERMINATE) divergences.push({c:{id:'11 dep throws',spec:O.INDETERMINATE},hn:'n/a',rf});
})();

// ---- policy-function conformance (floor + timestamp) — end-to-end needs mining --------
console.log('\n--- policy function (floor + timestamp): headers-node.headerPolicy vs reference.validateHeaderDifficulty ---');
function mutHdr(patch){ const b = Buffer.from(E.blockHeader,'hex'); if(patch.bits!=null)b.writeUInt32LE(patch.bits,72); if(patch.ts!=null)b.writeUInt32LE(patch.ts,68); return b.toString('hex'); }
const polCases = [
  ['real header (valid)',   mutHdr({}),                true],
  ['sub-floor (256x)',      mutHdr({bits:0x19227b71}), false],
  ['pre-genesis timestamp', mutHdr({ts:100}),          false],
  ['far-future timestamp',  mutHdr({ts:4000000000}),   false],
];
let polAgree=0;
for (const [name,h,exp] of polCases){
  const hn = HN.headerPolicy(h).valid;
  let rf; try { rf = ref.validateHeaderDifficulty(h).valid; } catch(e){ rf='ERR'; }
  const ok = (hn===rf && hn===exp); polAgree += ok?1:0;
  console.log('  '+pad(name,24)+' hn='+pad(hn,6)+' ref='+pad(rf,6)+' spec='+pad(exp,6)+(ok?'OK':'DIVERGE'));
  if(!ok) divergences.push({c:{id:'policy '+name,spec:exp},hn,rf});
}

// ---- legacy-proof differential (independent oracle-generated proofs) -----------------
console.log('\n--- legacy proof (natural byte order, per clarified §B) ---');
const csha=(b)=>crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest();
const toNat=(h)=>Buffer.from(h,'hex').reverse(), toDisp=(b)=>Buffer.from(b).reverse().toString('hex');
function oracleTree(txids){ let cur=txids.map(toNat); const L=[cur.slice()]; while(cur.length>1){const nx=[];for(let i=0;i<cur.length;i+=2)nx.push(csha(Buffer.concat([cur[i],(i+1<cur.length)?cur[i+1]:cur[i]])));L.push(nx.slice());cur=nx;} return {L,root:toDisp(L[L.length-1][0])}; }
function oracleProof(t,idx){ const p=[]; for(let h=0;h<t.L.length-1;h++){const pos=idx>>h,sib=pos^1;const s=(sib<t.L[h].length)?t.L[h][sib]:t.L[h][pos];p.push({hash:s.toString('hex'),pos:(pos&1)?'L':'R'});} return p; }
const txs = Array.from({length:9},()=>crypto.randomBytes(32).toString('hex'));
const T = oracleTree(txs); const idx=3; const goodProof = oracleProof(T,idx);
const lp = [
  ['valid legacy proof',  { txid:txs[idx], proof:goodProof, root:T.root }, true],
  ['wrong sibling',       { txid:txs[idx], proof:goodProof.map((s,i)=>i===0?{hash:'ff'+s.hash.slice(2),pos:s.pos}:s), root:T.root }, false],
  ['wrong txid',          { txid:crypto.randomBytes(32).toString('hex'), proof:goodProof, root:T.root }, false],
  ['wrong root',          { txid:txs[idx], proof:goodProof, root:'00'.repeat(32) }, false],
];
let lpAgree=0;
for (const [name,c,exp] of lp){
  const hn = (HN.merkleRootFromLegacy(c.txid,c.proof) === c.root);
  let rf; try { rf = ref.verifyMerkleProof(c.txid,c.proof,c.root); } catch(e){ rf='ERR'; }
  const ok = (hn===rf && hn===exp); lpAgree += ok?1:0;
  console.log('  '+pad(name,22)+' hn='+pad(hn,6)+' ref='+pad(rf,6)+' spec='+pad(exp,6)+(ok?'OK':'DIVERGE'));
  if(!ok) divergences.push({c:{id:'legacy '+name,spec:exp},hn,rf});
}
console.log('  policy-fn: '+polAgree+'/'+polCases.length+'   legacy-proof: '+lpAgree+'/'+lp.length);

// ---- evidence-identity invariants (A/B/C/D) for headers-node ------------------------
console.log('\n--- evidence identity (headers-node) ---');
const idBase = { txid:'ab'.repeat(32), blockHeader:'01'.repeat(80), proof:[{hash:'cd'.repeat(32),pos:'L'}], rawTx:'00', bump:'aa' };
const idOf = (o)=>HN.evidenceIdentity(Object.assign({},idBase,o));
const A = idOf({bump:'aa'})!==idOf({bump:'bb'});
const B1 = idOf({bump:undefined})!==idOf({bump:''});
const B2 = idOf({rawTx:undefined})!==idOf({rawTx:''});
const D = idOf({vout:0,satoshis:1,confirmations:9,blockHash:'z'})===idOf({vout:9,satoshis:99,confirmations:1,blockHash:'q'});
console.log('  A differing bump -> differing id :', A);
console.log('  B absent != empty (bump, rawTx)  :', B1 && B2);
console.log('  D advisory/display fields ignored:', D);
// C (committed context) is structural: checkpoint/tolerance/version are constants in the digest.

console.log('\n=== SUMMARY ===');
console.log('outcome cases:', total, '| headers-node == spec:', hnMatch, '| reference == spec:', refMatch, '| both == spec:', bothMatch);
console.log('identity invariants A/B/D:', (A&&B1&&B2&&D)?'all hold':'FAILURE');
console.log('divergences to investigate:', divergences.length);
