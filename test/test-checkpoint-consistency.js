/*
 * test-checkpoint-consistency.js — assert every active checkpoint definition agrees.
 * Run: node test/test-checkpoint-consistency.js   (from the repo root)
 *
 * WHY THIS EXISTS
 * ---------------
 * The checkpoint triple (height, hash, nBits) is the project's single trust anchor: every
 * VERIFIED and VERIFIED-ISOLATION outcome is conditional on it. It is hardcoded in FIVE
 * places, in two languages, and before this test nothing asserted they agreed. Measured on
 * the tree at 92c1f58: corrupting `nBits` in lib/headers.js — the value that sets the
 * difficulty floor for every verification — left the full suite reporting
 * ALL SUITES PASSED (23/23), and corrupting the hash in lib/mainnet-vectors.js was invisible
 * because no Node suite loads that file at all.
 *
 * The copies are deliberate and are NOT consolidated here. headers-node/ and
 * headers-node-independent/ are independent reimplementations; making them import the
 * production constant would destroy the independence that makes their agreement meaningful
 * (each requires only Node's `crypto` — verified: zero `lib/` imports). verify_vectors.py is
 * a different language. The correct remedy is an assertion that they agree, not a shared
 * import.
 *
 * WHAT THIS TEST DOES AND DOES NOT ESTABLISH
 * ------------------------------------------
 * Establishes: the five definitions are mutually identical on all three fields, and none has
 * silently disappeared.
 *
 * Does NOT establish: that the checkpoint is authentic, that block 939999 exists, that this
 * is its real hash or nBits, or that it is on the most-work chain. No offline test can.
 * External authenticity is a human control — see docs/CROSS-VERIFICATION.md and
 * docs/CHECKPOINT-PROVENANCE.md. This test only catches drift between copies.
 *
 * DESIGN NOTES
 * ------------
 * - The four JavaScript definitions are read as LIVE VALUES (require / module exports), not
 *   by matching source text, so the test asserts the value actually in use.
 * - verify_vectors.py is read by regex over its source. The test deliberately does not
 *   execute Python: this keeps `npm test` pure Node, offline and dependency-free.
 * - DEFINITIONS is a pinned list. A missing file, a missing export, or an unparseable
 *   definition is a FAILURE, not a skip — otherwise deleting a copy would quietly reduce
 *   coverage while the test still reported success.
 * - No network, no Git, no clock dependency. Runs from a bare directory copy.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

let pass = 0, fail = 0;
const failures = [];
function check(name, cond, detail) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else {
    fail++; failures.push(name);
    console.log('FAIL ' + name + (detail ? '  [' + detail + ']' : ''));
  }
}

// ---------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------
// Compare semantically, not textually: hex case and 0x-prefixed vs decimal nBits are
// presentation, not disagreement. The hash is compared in FULL — never a prefix.
function norm(raw, where) {
  if (!raw || typeof raw !== 'object') throw new Error('no checkpoint object in ' + where);
  const height = raw.height;
  const hash = raw.hash;
  const nBits = raw.nBits;
  if (typeof height !== 'number' || !Number.isInteger(height)) {
    throw new Error('height missing or not an integer in ' + where);
  }
  if (typeof hash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hash)) {
    throw new Error('hash missing or not 64 hex chars in ' + where);
  }
  if (typeof nBits !== 'number' || !Number.isInteger(nBits)) {
    throw new Error('nBits missing or not an integer in ' + where);
  }
  return { height: height, hash: hash.toLowerCase(), nBits: nBits >>> 0 };
}

// ---------------------------------------------------------------------------
// The five active definitions
// ---------------------------------------------------------------------------
const DEFINITIONS = [
  {
    id: 'lib/headers.js',
    note: 'canonical; shared by every browser tool',
    load: function () {
      // lib/headers.js attaches its exports to `window` in a browser and to `global` in
      // Node. Requiring it is how the existing Node suites reach CHECKPOINT.
      require(path.join(ROOT, 'lib/crypto.js'));
      require(path.join(ROOT, 'lib/encoding.js'));
      require(path.join(ROOT, 'lib/headers.js'));
      return norm(global.CHECKPOINT, 'global.CHECKPOINT');
    }
  },
  {
    id: 'lib/mainnet-vectors.js',
    note: 'CHECKPOINT_VERIFICATION, used by the browser test pages',
    load: function () {
      const m = require(path.join(ROOT, 'lib/mainnet-vectors.js'));
      if (!m || !m.CHECKPOINT_VERIFICATION) {
        throw new Error('CHECKPOINT_VERIFICATION not exported');
      }
      return norm(m.CHECKPOINT_VERIFICATION.checkpoint, 'CHECKPOINT_VERIFICATION.checkpoint');
    }
  },
  {
    id: 'headers-node/verify.js',
    note: 'spec-derived verifier #1 (independent; requires only node crypto)',
    load: function () {
      const m = require(path.join(ROOT, 'headers-node/verify.js'));
      return norm(m.CHECKPOINT, 'headers-node CHECKPOINT');
    }
  },
  {
    id: 'headers-node-independent/verify.js',
    note: 'spec-derived verifier #2 (independent; requires only node crypto)',
    load: function () {
      const m = require(path.join(ROOT, 'headers-node-independent/verify.js'));
      return norm(m.CHECKPOINT, 'headers-node-independent CHECKPOINT');
    }
  },
  {
    id: 'verify_vectors.py',
    note: 'Python cross-verification vectors (parsed from source; Python is not executed)',
    load: function () {
      const p = path.join(ROOT, 'verify_vectors.py');
      if (!fs.existsSync(p)) throw new Error('file not found');
      const src = fs.readFileSync(p, 'utf8');
      // Isolate the "checkpoint" entry FIRST, then match inside it. verify_vectors.py also
      // defines vector1/2/3, each with its own "block_hash" and "block_height"; an
      // unscoped match picks up genesis instead of the checkpoint and the test compares
      // the wrong thing. Scoping is required for correctness, not tidiness.
      const block = src.match(/"checkpoint"\s*:\s*\{([\s\S]*?)\}/);
      if (!block) throw new Error('could not locate the "checkpoint" entry (file reformatted?)');
      const cpSrc = block[1];
      const mHash   = cpSrc.match(/"block_hash"\s*:\s*"([0-9a-fA-F]{64})"/);
      const mHeight = cpSrc.match(/"block_height"\s*:\s*(\d+)/);
      const mBits   = cpSrc.match(/"nbits"\s*:\s*(0[xX][0-9a-fA-F]+|\d+)/);
      if (!mHash)   throw new Error('could not parse checkpoint "block_hash" (file reformatted?)');
      if (!mHeight) throw new Error('could not parse checkpoint "block_height" (file reformatted?)');
      if (!mBits)   throw new Error('could not parse checkpoint "nbits" (file reformatted?)');
      return norm({
        height: parseInt(mHeight[1], 10),
        hash: mHash[1],
        nBits: /^0[xX]/.test(mBits[1]) ? parseInt(mBits[1], 16) : parseInt(mBits[1], 10)
      }, 'verify_vectors.py');
    }
  }
];

console.log('=== checkpoint consistency across all active definitions ===\n');

// ---------------------------------------------------------------------------
// CP-0: every pinned definition must be present and parseable.
// A removed or renamed definition fails here. It is never skipped.
// ---------------------------------------------------------------------------
const loaded = [];
for (const def of DEFINITIONS) {
  let cp = null, err = null;
  try { cp = def.load(); } catch (e) { err = e.message; }
  check('CP-0 definition present and parseable: ' + def.id, cp !== null, err || '');
  loaded.push({ id: def.id, note: def.note, cp: cp });
}

const present = loaded.filter(function (l) { return l.cp !== null; });

check('CP-0 all ' + DEFINITIONS.length + ' expected definitions were found',
  present.length === DEFINITIONS.length,
  'found ' + present.length + ' of ' + DEFINITIONS.length);

if (present.length === 0) {
  console.log('\n----------------------------------------');
  console.log('PASSED: ' + pass + '   FAILED: ' + fail);
  console.log('\nNo checkpoint definition could be read at all. The test cannot compare');
  console.log('anything, which is itself a failure.');
  process.exit(1);
}

// Print what was read, so a failure is diagnosable from the output alone.
console.log('');
for (const l of present) {
  console.log('  ' + l.id);
  console.log('      height ' + l.cp.height +
              '   nBits 0x' + l.cp.nBits.toString(16) +
              '\n      hash   ' + l.cp.hash);
}
console.log('');

// ---------------------------------------------------------------------------
// CP-1..CP-3: all three fields must agree across every definition.
// The reference is lib/headers.js when available (the canonical definition), else the
// first that loaded — so the test still compares the rest if the canonical one is missing.
// ---------------------------------------------------------------------------
const ref = (loaded[0] && loaded[0].cp) ? loaded[0] : present[0];
console.log('Reference definition: ' + ref.id + '\n');

const FIELDS = [
  { tag: 'CP-1', name: 'height', fmt: function (v) { return String(v); } },
  { tag: 'CP-2', name: 'hash',   fmt: function (v) { return v; } },             // full hash
  { tag: 'CP-3', name: 'nBits',  fmt: function (v) { return '0x' + v.toString(16); } }
];

for (const f of FIELDS) {
  for (const l of present) {
    if (l.id === ref.id) continue;
    const same = l.cp[f.name] === ref.cp[f.name];
    check(f.tag + ' ' + f.name + ' agrees: ' + l.id, same,
      same ? '' : 'got ' + f.fmt(l.cp[f.name]) + ', reference has ' + f.fmt(ref.cp[f.name]));
  }
}

// ---------------------------------------------------------------------------
// CP-4: the triple is internally well-formed. These are sanity properties of the
// values themselves, not authenticity claims.
// ---------------------------------------------------------------------------
check('CP-4 height is a positive integer', ref.cp.height > 0, String(ref.cp.height));
check('CP-4 hash is 64 lowercase hex chars', /^[0-9a-f]{64}$/.test(ref.cp.hash));
check('CP-4 nBits decodes to a positive target', (function () {
  const exp = ref.cp.nBits >>> 24;
  const mant = ref.cp.nBits & 0x00ffffff;
  return exp > 3 && mant > 0;
})(), '0x' + ref.cp.nBits.toString(16));
// The checkpoint's own hash must satisfy the difficulty its own nBits declares. This is an
// internal-consistency property of the triple: a hash/nBits pair that fails it could not be
// the same block. It is NOT evidence that the block is real or canonical.
check('CP-4 checkpoint hash is below the target implied by its own nBits', (function () {
  const exp = ref.cp.nBits >>> 24;
  const mant = BigInt(ref.cp.nBits & 0x00ffffff);
  const target = mant << BigInt(8 * (exp - 3));
  return BigInt('0x' + ref.cp.hash) <= target;
})());

// ---------------------------------------------------------------------------
console.log('\n----------------------------------------');
console.log('PASSED: ' + pass + '   FAILED: ' + fail);

if (fail > 0) {
  console.log('\nCHECKPOINT DEFINITIONS DISAGREE, or an expected definition is missing.');
  console.log('The trust anchor is hardcoded in ' + DEFINITIONS.length + ' places; they must be');
  console.log('changed together. Failing assertions:');
  for (const f of failures) console.log('  - ' + f);
  console.log('\nIf you are intentionally changing the checkpoint, update every definition');
  console.log('listed above in the same commit, and record the change as described in');
  console.log('docs/CHECKPOINT-PROVENANCE.md.');
  process.exit(1);
}

console.log('\nAll ' + present.length + ' definitions agree on height, full hash and nBits.');
console.log('This is drift detection only — it is NOT evidence that the checkpoint is');
console.log('authentic or canonical. See docs/CHECKPOINT-PROVENANCE.md.');
process.exit(0);
