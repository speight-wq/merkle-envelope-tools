/**
 * secp256k1.js - Elliptic curve operations
 * Merkle Envelope Tools
 * Depends on: crypto.js, encoding.js
 */
(function(global) {
  'use strict';

  const P = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');
  const N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
  const Gx = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
  const Gy = BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');
  const HALF_N = N / 2n;

  function mod(a, m) { const r = a % m; return r >= 0n ? r : r + m; }

  function modInverse(a, m) {
    if (a < 0n) a = mod(a, m);
    let [old_r, r] = [a, m], [old_s, s] = [1n, 0n];
    while (r !== 0n) {
      const q = old_r / r;
      [old_r, r] = [r, old_r - q * r];
      [old_s, s] = [s, old_s - q * s];
    }
    return mod(old_s, m);
  }

  function modPow(base, exp, m) {
    let result = 1n;
    base = mod(base, m);
    while (exp > 0n) {
      if (exp & 1n) result = mod(result * base, m);
      exp >>= 1n;
      base = mod(base * base, m);
    }
    return result;
  }

  function pointAdd(p1, p2) {
    if (p1 === null) return p2;
    if (p2 === null) return p1;
    const [x1, y1] = p1, [x2, y2] = p2;
    if (x1 === x2) {
      if (mod(y1 + y2, P) === 0n) return null;
      const s = mod(3n * x1 * x1 * modInverse(2n * y1, P), P);
      const x3 = mod(s * s - 2n * x1, P);
      return [x3, mod(s * (x1 - x3) - y1, P)];
    }
    const s = mod((y2 - y1) * modInverse(x2 - x1, P), P);
    const x3 = mod(s * s - x1 - x2, P);
    return [x3, mod(s * (x1 - x3) - y1, P)];
  }

  function pointMul(k, point) {
    let result = null, addend = point;
    while (k > 0n) {
      if (k & 1n) result = pointAdd(result, addend);
      addend = pointAdd(addend, addend);
      k >>= 1n;
    }
    return result;
  }

  function getPublicKey(privateKeyHex, compressed = true) {
    const d = BigInt('0x' + privateKeyHex);
    if (d <= 0n || d >= N) throw new Error('Invalid private key');
    const point = pointMul(d, [Gx, Gy]);
    const x = point[0].toString(16).padStart(64, '0');
    const y = point[1].toString(16).padStart(64, '0');
    if (compressed) return ((point[1] & 1n) === 0n ? '02' : '03') + x;
    return '04' + x + y;
  }

  function parsePublicKey(pubKeyHex) {
    const bytes = global.hexToBytes(pubKeyHex);
    if (bytes[0] === 0x04 && bytes.length === 65) {
      return [BigInt('0x' + global.bytesToHex(bytes.slice(1, 33))),
              BigInt('0x' + global.bytesToHex(bytes.slice(33, 65)))];
    }
    if ((bytes[0] === 0x02 || bytes[0] === 0x03) && bytes.length === 33) {
      const x = BigInt('0x' + global.bytesToHex(bytes.slice(1)));
      const ySquared = mod(x * x * x + 7n, P);
      let y = modPow(ySquared, (P + 1n) / 4n, P);
      if (((y & 1n) === 1n) !== (bytes[0] === 0x03)) y = P - y;
      return [x, y];
    }
    throw new Error('Invalid public key format');
  }

  function generateK(messageHashHex, privateKeyHex) {
    const hashBytes = global.hexToBytes(messageHashHex);
    const privBytes = global.hexToBytes(privateKeyHex);
    let v = new Uint8Array(32).fill(0x01);
    let k = new Uint8Array(32).fill(0x00);
    const data0 = new Uint8Array(97);
    data0.set(v, 0); data0[32] = 0x00; data0.set(privBytes, 33); data0.set(hashBytes, 65);
    k = global.hmacSha256(k, data0);
    v = global.hmacSha256(k, v);
    const data1 = new Uint8Array(97);
    data1.set(v, 0); data1[32] = 0x01; data1.set(privBytes, 33); data1.set(hashBytes, 65);
    k = global.hmacSha256(k, data1);
    v = global.hmacSha256(k, v);
    while (true) {
      v = global.hmacSha256(k, v);
      const candidate = BigInt('0x' + global.bytesToHex(v));
      if (candidate > 0n && candidate < N) return candidate;
      const retry = new Uint8Array(33);
      retry.set(v, 0); retry[32] = 0x00;
      k = global.hmacSha256(k, retry);
      v = global.hmacSha256(k, v);
    }
  }

  function sign(messageHashHex, privateKeyHex) {
    const z = BigInt('0x' + messageHashHex);
    const d = BigInt('0x' + privateKeyHex);
    const k = generateK(messageHashHex, privateKeyHex);
    const point = pointMul(k, [Gx, Gy]);
    const r = mod(point[0], N);
    if (r === 0n) throw new Error('Invalid signature (r=0)');
    let s = mod(modInverse(k, N) * (z + r * d), N);
    if (s === 0n) throw new Error('Invalid signature (s=0)');
    if (s > HALF_N) s = N - s;
    return { r, s };
  }

  function signatureToDER(r, s) {
    function intToBytes(n) {
      let hex = n.toString(16);
      if (hex.length % 2) hex = '0' + hex;
      const bytes = global.hexToBytes(hex);
      if (bytes[0] & 0x80) {
        const padded = new Uint8Array(bytes.length + 1);
        padded.set(bytes, 1);
        return padded;
      }
      return bytes;
    }
    const rBytes = intToBytes(r), sBytes = intToBytes(s);
    const totalLen = 2 + rBytes.length + 2 + sBytes.length;
    const der = new Uint8Array(2 + totalLen);
    let offset = 0;
    der[offset++] = 0x30; der[offset++] = totalLen;
    der[offset++] = 0x02; der[offset++] = rBytes.length;
    der.set(rBytes, offset); offset += rBytes.length;
    der[offset++] = 0x02; der[offset++] = sBytes.length;
    der.set(sBytes, offset);
    return global.bytesToHex(der);
  }

  function parseDER(derHex) {
    const bytes = global.hexToBytes(derHex);
    let offset = 0;
    if (bytes[offset++] !== 0x30) throw new Error('Invalid DER');
    offset++; // skip length
    if (bytes[offset++] !== 0x02) throw new Error('Invalid DER');
    const rLen = bytes[offset++];
    let r = 0n;
    for (let i = 0; i < rLen; i++) r = (r << 8n) | BigInt(bytes[offset++]);
    if (bytes[offset++] !== 0x02) throw new Error('Invalid DER');
    const sLen = bytes[offset++];
    let s = 0n;
    for (let i = 0; i < sLen; i++) s = (s << 8n) | BigInt(bytes[offset++]);
    return { r, s };
  }

  function verify(messageHashHex, signatureHex, publicKeyHex) {
    try {
      const { r, s } = parseDER(signatureHex);
      const z = BigInt('0x' + messageHashHex);
      const pubKey = parsePublicKey(publicKeyHex);
      if (r <= 0n || r >= N || s <= 0n || s >= N) return false;
      const sInv = modInverse(s, N);
      const u1 = mod(z * sInv, N), u2 = mod(r * sInv, N);
      const p1 = pointMul(u1, [Gx, Gy]);
      const p2 = pointMul(u2, pubKey);
      const point = pointAdd(p1, p2);
      return point !== null && mod(point[0], N) === r;
    } catch { return false; }
  }

  function wifToPrivateKey(wif) {
    const decoded = global.base58CheckDecode(wif);
    if (decoded.version !== 0x80 && decoded.version !== 0xef) throw new Error('Invalid WIF version');
    let hash = decoded.hash, compressed = false;
    if (hash.length === 33 && hash[32] === 0x01) {
      compressed = true;
      hash = hash.slice(0, 32);
    } else if (hash.length !== 32) throw new Error('Invalid WIF length');
    return { privateKey: global.bytesToHex(hash), compressed };
  }

  global.SECP256K1 = { P, N, Gx, Gy, HALF_N, getPublicKey, parsePublicKey, sign, verify, signatureToDER, parseDER, wifToPrivateKey };
})(typeof window !== 'undefined' ? window : global);
