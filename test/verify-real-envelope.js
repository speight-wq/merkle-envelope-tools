require('../lib/crypto.js');require('../lib/encoding.js');require('../lib/headers.js');
const BUMP=require('../lib/bump.js');
const H=global, e=JSON.parse(require('fs').readFileSync(__dirname+'/real-envelope.json','utf8'));
function headerMerkleRoot(hx){return H.reverseHex(hx.slice(72,136));}
console.log('blockHeader length (hex chars):', e.blockHeader.length, e.blockHeader.length===160?'(80 bytes OK)':'(WRONG)');
const hdr=H.parseHeader(e.blockHeader);
console.log('nBits: 0x'+hdr.nBits.toString(16),' timestamp:',new Date(hdr.timestamp*1000).toISOString());
// 1. txid == hash256(rawTx)?
const txid=H.reverseHex(H.bytesToHex(H.hash256(e.rawTx)));
console.log('1. txid matches SHA256d(rawTx):', txid===e.txid);
// 2. legacy proof reproduces header merkle root?
const hRoot=headerMerkleRoot(e.blockHeader);
const legacyOk=H.verifyMerkleProof(e.txid,e.proof,hRoot);
console.log('2. legacy proof -> header merkle root:', legacyOk);
console.log('   header merkleRoot:', hRoot);
// 3. BUMP reproduces the same root?
const bump=BUMP.fromHex(e.bump);
const bumpRootDisplay=BUMP.merkleRoot(bump,e.txid);
console.log('3. BUMP root === header root:', bumpRootDisplay===hRoot, '(bump txid present:', bump.path[0].some(l=>l.hash===e.txid)+')');
// 4. PoW valid?
console.log('4. verifyPoW:', H.verifyPoW(e.blockHeader), ' blockHash:', H.hashHeader(e.blockHeader));
console.log('   claimed blockHash matches:', H.hashHeader(e.blockHeader)===e.blockHash);
// 5. difficulty floor (the patched gate) — does a REAL header pass?
const floor=H.validateHeaderDifficulty(e.blockHeader);
console.log('5. validateHeaderDifficulty (floor gate):', floor.valid, floor.reason||'');
const eff=H.getEffectiveFloor();
console.log('   header target:', H.targetFromNBits(hdr.nBits).toString(16).slice(0,20)+'...');
console.log('   floor  target:', eff.target.toString(16).slice(0,20)+'...', '('+eff.source+')');
console.log('   header harder than floor (target<=floor):', H.targetFromNBits(hdr.nBits)<=eff.target);
// 6. CVE guard on the legacy proof
console.log('6. checkMerkleProofSafe(legacy proof):', H.checkMerkleProofSafe(e.proof));
