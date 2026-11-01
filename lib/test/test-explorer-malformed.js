'use strict';
/*
 * test/test-explorer-malformed.js - regression for the Phase-4A fix.
 *
 * validateProofStructure() previously checked proof-hash / txid LENGTH but not hex-validity,
 * so a 64-char non-hex value (or an odd-length value reaching an earlier decode) threw an
 * uncaught "Invalid hex characters" out of explorer.html verify() instead of returning the
 * typed MALFORMED outcome. These cases assert verify() returns MALFORMED and NEVER throws,
 * while genuinely valid upper/lowercase hex still verifies.
 *
 * Drives the SHIPPED explorer verify() via the same DOM-stub extraction the other harnesses use.
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
require(path.join(ROOT, 'lib/crypto.js'));
require(path.join(ROOT, 'lib/encoding.js'));
require(path.join(ROOT, 'lib/headers.js'));
const ENV = JSON.parse(fs.readFileSync(path.join(ROOT, 'test/real-envelope.json'), 'utf8'));

function loadExplorerVerify() {
  const c = {}; c.global = c; c.performance = { now: () => 0 }; c.TextEncoder = TextEncoder;
  c.console = { log() {}, warn() {}, error() {} }; c.Date = Date;
  vm.createContext(c);
  for (const f of ['crypto.js', 'encoding.js', 'headers.js']) vm.runInContext(fs.readFileSync(path.join(ROOT, 'lib', f), 'utf8'), c);
  const h = fs.readFileSync(path.join(ROOT, 'explorer.html'), 'utf8');
  const s = h.indexOf('function sha256Single');
  const m = "return 'Corrupted branch, wrong sibling, or mismatched header';\n    }";
  vm.runInContext(h.slice(s, h.indexOf(m) + m.length), c);
  return c;
}
const ctx = loadExplorerVerify();
ctx.chainHashIndex = null; ctx.chainLoadFailed = false;

let pass = 0, fail = 0;
function ok(cond, msg) { if (cond) { pass++; console.log('PASS ' + msg); } else { fail++; console.log('FAIL ' + msg); } }

// returns { outcome } or { threw } - the key property is that it must NOT throw
function run(env) {
  try { const r = ctx.verify(env); return { outcome: r.result.outcome }; }
  catch (e) { return { threw: e.message }; }
}
const base = () => { const e = JSON.parse(JSON.stringify(ENV)); delete e.bump; return e; }; // explorer verdict path = legacy proof

// 1. 64-char non-hex proof hash -> MALFORMED, no throw
let r = run(Object.assign(base(), { proof: [{ hash: 'g'.repeat(64), pos: 'L' }] }));
ok(!r.threw && r.outcome === 'MALFORMED', '64-char non-hex proof hash -> MALFORMED (no throw) [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome) + ']');

// 2. odd-length proof hash -> MALFORMED, no throw
r = run(Object.assign(base(), { proof: [{ hash: 'ab'.repeat(31) + 'a', pos: 'L' }] }));
ok(!r.threw && r.outcome === 'MALFORMED', 'odd-length proof hash -> MALFORMED (no throw) [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome) + ']');

// 3. 64-char non-hex txid -> MALFORMED, no throw
r = run(Object.assign(base(), { txid: 'z'.repeat(64) }));
ok(!r.threw && r.outcome === 'MALFORMED', '64-char non-hex txid -> MALFORMED (no throw) [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome) + ']');

// 4. odd-length txid -> MALFORMED, no throw
r = run(Object.assign(base(), { txid: 'ab'.repeat(31) + 'a' }));
ok(!r.threw && r.outcome === 'MALFORMED', 'odd-length txid -> MALFORMED (no throw) [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome) + ']');

// 5. valid lowercase hex still accepted (baseline)
r = run(base());
ok(!r.threw && r.outcome === 'VERIFIED-ISOLATION', 'valid lowercase hex still VERIFIED-ISOLATION [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome) + ']');

// 6. valid UPPERCASE hex still accepted (case-insensitive hex preserved)
r = run(Object.assign(base(), { txid: ENV.txid.toUpperCase() }));
ok(!r.threw && r.outcome === 'VERIFIED-ISOLATION', 'valid UPPERCASE txid still VERIFIED-ISOLATION [got ' + (r.threw ? 'THREW:' + r.threw : r.outcome) + ']');

console.log('\n----------------------------------------');
console.log('PASSED: ' + pass + '   FAILED: ' + fail);
process.exit(fail ? 1 : 0);
