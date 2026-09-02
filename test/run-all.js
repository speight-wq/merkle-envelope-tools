'use strict';
/*
 * test/run-all.js - one reproducible entry point for the existing Node-side suites.
 *
 * This aggregator does NOT contain any test logic. It runs each existing suite as its own
 * child process (so their exit codes, isolation, and independence are preserved), reports
 * which suite is running, and fails if any suite fails. Paths are resolved relative to the
 * repository root (this file's parent), so it works from a clean checkout with no
 * environment variables, no /home/claude paths, and no network.
 *
 * Run:  npm test    (or)    node test/run-all.js
 */
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');

// Ordered: fast library self-tests, then unit/adversarial, then the independent
// differential validator, then the DOM-stub integration harnesses, then the two
// spec-derived conformance implementations. Each entry is an independent process.
const SUITES = [
  { name: 'lib/bump.js self-test',            cmd: 'lib/bump.js' },
  { name: 'lib/beef.js self-test',            cmd: 'lib/beef.js' },
  { name: 'test/test-audit-fixes.js',         cmd: 'test/test-audit-fixes.js' },
  { name: 'test/test-adversarial.js',         cmd: 'test/test-adversarial.js' },
  { name: 'test/validate.js (independent)',   cmd: 'test/validate.js' },
  { name: 'test/test-generator.js',           cmd: 'test/test-generator.js' },
  { name: 'test/test-integration.js',         cmd: 'test/test-integration.js' },
  { name: 'test/test-explorer-malformed.js',  cmd: 'test/test-explorer-malformed.js' },
  { name: 'test/test-verifier-malformed.js',  cmd: 'test/test-verifier-malformed.js' },
  { name: 'test/test-chain.js',               cmd: 'test/test-chain.js' },
  { name: 'headers-node/conformance.js',      cmd: 'headers-node/conformance.js' },
  { name: 'headers-node-independent/selftest.js', cmd: 'headers-node-independent/selftest.js' },
  { name: 'test/fuzz.js (deterministic, seed 20260101, 20k iters)', cmd: 'test/fuzz.js', args: ['--seed', '20260101', '--iters', '20000'] },
  { name: 'test/fuzz-browser.js (shipped explorer verify(), seed 20260301, 20k iters)', cmd: 'test/fuzz-browser.js', args: ['--seed', '20260301', '--iters', '20000'] },
  { name: 'test/fuzz-verifier-browser.js (shipped verifier verify(), seed 20260401, 20k iters)', cmd: 'test/fuzz-verifier-browser.js', args: ['--seed', '20260401', '--iters', '20000'] }
];

// A suite is a failure if the process exits non-zero OR its output reports a non-zero
// failure count (belt-and-braces: some suites print FAILED/FAIL totals). We never swallow
// output - it is streamed through so a stranger sees exactly what ran.
function isReportedFailure(out) {
  return /\bFAIL(?:ED)?:?\s*[1-9]\d*\b/i.test(out);
}

let failed = 0;
const results = [];

for (const suite of SUITES) {
  process.stdout.write('\n=== ' + suite.name + ' ===\n');
  const r = spawnSync(process.execPath, [path.join(ROOT, suite.cmd), ...(suite.args || [])], {
    cwd: ROOT,
    encoding: 'utf8'
  });
  const out = (r.stdout || '') + (r.stderr || '');
  process.stdout.write(out.endsWith('\n') ? out : out + '\n');

  const crashed = r.status === null || typeof r.status === 'undefined';
  const bad = crashed || r.status !== 0 || isReportedFailure(r.stdout || '');
  if (bad) failed++;
  results.push({
    name: suite.name,
    status: crashed ? 'CRASH (' + (r.error && r.error.message) + ')'
          : bad ? 'FAIL (exit ' + r.status + ')'
          : 'pass'
  });
}

process.stdout.write('\n========================================\n');
process.stdout.write('SUMMARY\n');
for (const res of results) {
  process.stdout.write('  ' + (res.status === 'pass' ? 'PASS' : 'FAIL') + '  ' + res.name +
    (res.status === 'pass' ? '' : '  -> ' + res.status) + '\n');
}
process.stdout.write('----------------------------------------\n');
process.stdout.write((failed === 0 ? 'ALL SUITES PASSED' : failed + ' SUITE(S) FAILED') +
  ' (' + (results.length - failed) + '/' + results.length + ')\n');

process.exit(failed === 0 ? 0 : 1);
