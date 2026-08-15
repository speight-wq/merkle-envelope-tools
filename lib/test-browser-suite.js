'use strict';
const fs = require('fs');
const vm = require('vm');

const ctx = {};
ctx.global = ctx; ctx.console = console; ctx.Date = Date; ctx.Map = Map;
ctx.TextEncoder = TextEncoder; ctx.performance = { now: () => 0 };
vm.createContext(ctx);
for (const f of ['crypto.js', 'encoding.js', 'headers.js', 'bump.js', 'beef.js'])
  vm.runInContext(fs.readFileSync('/home/claude/' + f, 'utf8'), ctx);

// same harness tests.html uses
vm.runInContext(`
  var results = [];
  function test(name, fn) {
    try { var r = fn(); results.push({ name: name, pass: r === true, error: r === true ? null : 'returned ' + JSON.stringify(r) }); }
    catch (e) { results.push({ name: name, pass: false, error: e.message }); }
  }
  function assertEqual(actual, expected, msg) {
    if (actual !== expected) throw new Error((msg || 'Assertion failed') + ': expected ' + expected + ', got ' + actual);
  }
`, ctx);

// extract the new test blocks from tests.html and run them
const html = fs.readFileSync('/home/claude/tests.html', 'utf8');
const start = html.indexOf('// BUMP (BRC-74) tests');
const end = html.indexOf('// Render results');
vm.runInContext(html.slice(start, end), ctx);

const results = ctx.results;
let pass = 0, fail = 0;
for (const r of results) { r.pass ? pass++ : fail++; console.log((r.pass ? 'PASS ' : 'FAIL ') + r.name + (r.error ? '  [' + r.error + ']' : '')); }
console.log('\n----------------------------------------');
console.log('NEW BROWSER TESTS  PASSED: ' + pass + '   FAILED: ' + fail);
process.exit(fail ? 1 : 0);
