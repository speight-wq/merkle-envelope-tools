/**
 * encoding.js - Data format conversions
 * Merkle Envelope Tools
 * 
 * Contents:
 *   - Hex conversion (hexToBytes, bytesToHex, reverseHex)
 *   - Integer encoding (varInt, writeUInt32LE, writeUInt64LE)
 *   - Base58Check encoding
 *   - Validation utilities
 * 
 * No dependencies.
 */
(function(global) {
  'use strict';

  // ==========================================
  // Validation Utilities
  // ==========================================

  /**
   * Strict hex validation - rejects non-canonical hex
   * Mitigates: Malformed input parsing, odd-length injection
   */
  function isValidHex(s) {
    return typeof s === 'string' && 
           s.length % 2 === 0 && 
           /^[a-f0-9]*$/i.test(s);
  }

  /**
   * Constant-time comparison for hash equality
   * Mitigates: Timing side-channel attacks on hash comparisons
   */
  function constantTimeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return diff === 0;
  }

  function hexToBytes(hex) {
    if (typeof hex !== 'string') throw new Error('Expected hex string');
    if (hex.length % 2 !== 0) throw new Error('Hex string must have even length');
    if (!/^[a-f0-9]*$/i.test(hex)) throw new Error('Invalid hex characters');
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  function bytesToHex(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  function reverseHex(hex) {
    return bytesToHex(hexToBytes(hex).reverse());
  }

  function varInt(n) {
    if (n < 0xfd) return n.toString(16).padStart(2, '0');
    if (n <= 0xffff) return 'fd' + writeUInt16LE(n);
    if (n <= 0xffffffff) return 'fe' + writeUInt32LE(n);
    return 'ff' + writeUInt64LE(n);
  }

  function writeUInt16LE(n) {
    return (n & 0xff).toString(16).padStart(2, '0') +
           ((n >>> 8) & 0xff).toString(16).padStart(2, '0');
  }

  function writeUInt32LE(n) {
    return (n & 0xff).toString(16).padStart(2, '0') +
           ((n >>> 8) & 0xff).toString(16).padStart(2, '0') +
           ((n >>> 16) & 0xff).toString(16).padStart(2, '0') +
           ((n >>> 24) & 0xff).toString(16).padStart(2, '0');
  }

  function writeUInt64LE(n) {
    const big = typeof n === 'bigint' ? n : BigInt(n);
    let hex = '';
    for (let i = 0; i < 8; i++) {
      hex += Number((big >> BigInt(i * 8)) & 0xffn).toString(16).padStart(2, '0');
    }
    return hex;
  }

  function readUInt32LE(hex, offset) {
    const bytes = hexToBytes(hex.substr(offset * 2, 8));
    return bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
  }

  function readUInt64LE(hex, offset) {
    const bytes = hexToBytes(hex.substr(offset * 2, 16));
    let value = 0n;
    for (let i = 0; i < 8; i++) value |= BigInt(bytes[i]) << BigInt(i * 8);
    return value;
  }

  const Base58 = (function() {
    const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    const ALPHABET_MAP = {};
    for (let i = 0; i < ALPHABET.length; i++) ALPHABET_MAP[ALPHABET[i]] = i;

    function encode(bytes) {
      if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
      let zeros = 0;
      while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
      const size = Math.ceil(bytes.length * 138 / 100) + 1;
      const b58 = new Uint8Array(size);
      let length = 0;
      for (let i = zeros; i < bytes.length; i++) {
        let carry = bytes[i];
        let j = 0;
        for (let k = size - 1; k >= 0 && (carry !== 0 || j < length); k--, j++) {
          carry += 256 * b58[k];
          b58[k] = carry % 58;
          carry = Math.floor(carry / 58);
        }
        length = j;
      }
      let it = size - length;
      while (it < size && b58[it] === 0) it++;
      let result = '1'.repeat(zeros);
      for (; it < size; it++) result += ALPHABET[b58[it]];
      return result;
    }

    function decode(str) {
      if (typeof str !== 'string') throw new Error('Expected string');
      if (str.length === 0) return new Uint8Array(0);
      let zeros = 0;
      while (zeros < str.length && str[zeros] === '1') zeros++;
      const size = Math.ceil(str.length * 733 / 1000) + 1;
      const b256 = new Uint8Array(size);
      let length = 0;
      for (let i = zeros; i < str.length; i++) {
        const value = ALPHABET_MAP[str[i]];
        if (value === undefined) throw new Error('Invalid Base58 character');
        let carry = value;
        let j = 0;
        for (let k = size - 1; k >= 0 && (carry !== 0 || j < length); k--, j++) {
          carry += 58 * b256[k];
          b256[k] = carry % 256;
          carry = Math.floor(carry / 256);
        }
        length = j;
      }
      let it = size - length;
      while (it < size && b256[it] === 0) it++;
      const result = new Uint8Array(zeros + (size - it));
      let j = zeros;
      for (; it < size; it++, j++) result[j] = b256[it];
      return result;
    }
    return { encode, decode };
  })();

  function base58CheckEncode(version, payload) {
    if (typeof payload === 'string') payload = hexToBytes(payload);
    const data = new Uint8Array(1 + payload.length);
    data[0] = version;
    data.set(payload, 1);
    const checksum = global.hash256(data).slice(0, 4);
    const full = new Uint8Array(data.length + 4);
    full.set(data);
    full.set(checksum, data.length);
    return Base58.encode(full);
  }

  function base58CheckDecode(address) {
    const bytes = Base58.decode(address);
    if (bytes.length < 5) throw new Error('Address too short');
    const payload = bytes.slice(0, -4);
    const checksum = bytes.slice(-4);
    const computed = global.hash256(payload).slice(0, 4);
    for (let i = 0; i < 4; i++) {
      if (checksum[i] !== computed[i]) throw new Error('Invalid checksum');
    }
    return { version: payload[0], hash: payload.slice(1) };
  }

  global.isValidHex = isValidHex;
  global.constantTimeEqual = constantTimeEqual;
  global.hexToBytes = hexToBytes;
  global.bytesToHex = bytesToHex;
  global.reverseHex = reverseHex;
  global.varInt = varInt;
  global.writeUInt16LE = writeUInt16LE;
  global.writeUInt32LE = writeUInt32LE;
  global.writeUInt64LE = writeUInt64LE;
  global.readUInt32LE = readUInt32LE;
  global.readUInt64LE = readUInt64LE;
  global.Base58 = Base58;
  global.base58CheckEncode = base58CheckEncode;
  global.base58CheckDecode = base58CheckDecode;
})(typeof window !== 'undefined' ? window : global);
