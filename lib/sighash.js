/**
 * sighash.js - BSV transaction sighash construction
 * Merkle Envelope Tools
 * Depends on: crypto.js, encoding.js
 */
(function(global) {
  'use strict';

  const SIGHASH_ALL = 0x01;
  const SIGHASH_FORKID = 0x40;
  const BSV_SIGHASH = SIGHASH_ALL | SIGHASH_FORKID;

  function computeSighashComponents(inputs, outputsHex) {
    let prevoutsData = '';
    for (const inp of inputs) {
      prevoutsData += global.reverseHex(inp.txid) + global.writeUInt32LE(inp.vout);
    }
    const hashPrevouts = global.bytesToHex(global.hash256(prevoutsData));
    const hashSequence = global.bytesToHex(global.hash256('ffffffff'.repeat(inputs.length)));
    const hashOutputs = global.bytesToHex(global.hash256(outputsHex));
    return { hashPrevouts, hashSequence, hashOutputs };
  }

  function buildSighashPreimage(input, components, version, locktime) {
    let preimage = global.writeUInt32LE(version);
    preimage += components.hashPrevouts;
    preimage += components.hashSequence;
    preimage += global.reverseHex(input.txid);
    preimage += global.writeUInt32LE(input.vout);
    const scriptCode = '76a914' + input.pubKeyHash + '88ac';
    preimage += global.varInt(scriptCode.length / 2);
    preimage += scriptCode;
    preimage += global.writeUInt64LE(input.satoshis);
    preimage += 'ffffffff';
    preimage += components.hashOutputs;
    preimage += global.writeUInt32LE(locktime);
    preimage += global.writeUInt32LE(BSV_SIGHASH);
    return preimage;
  }

  function computeSighash(input, components, version, locktime) {
    const preimage = buildSighashPreimage(input, components, version, locktime);
    return global.bytesToHex(global.hash256(preimage));
  }

  function computeSingleInputSighash(input, outputsHex, version, locktime) {
    const components = computeSighashComponents([input], outputsHex);
    return computeSighash(input, components, version, locktime);
  }

  global.SIGHASH_ALL = SIGHASH_ALL;
  global.SIGHASH_FORKID = SIGHASH_FORKID;
  global.BSV_SIGHASH = BSV_SIGHASH;
  global.computeSighashComponents = computeSighashComponents;
  global.buildSighashPreimage = buildSighashPreimage;
  global.computeSighash = computeSighash;
  global.computeSingleInputSighash = computeSingleInputSighash;
})(typeof window !== 'undefined' ? window : global);
