/**
 * crypto.js - Core cryptographic hash functions
 * No dependencies. Must be loaded first.
 */
(function(global) {
  'use strict';

  const SHA256_K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);

  const SHA256 = {
    hash: function(data) {
      if (typeof data === 'string') {
        const bytes = new Uint8Array(data.length / 2);
        for (let i = 0; i < data.length; i += 2) bytes[i/2] = parseInt(data.substr(i, 2), 16);
        data = bytes;
      }
      if (!(data instanceof Uint8Array)) data = new Uint8Array(data);
      const len = data.length, padLen = Math.ceil((len + 9) / 64) * 64;
      const padded = new Uint8Array(padLen);
      padded.set(data); padded[len] = 0x80;
      new DataView(padded.buffer).setUint32(padLen - 4, len * 8, false);
      let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
      const w = new Uint32Array(64), view = new DataView(padded.buffer);
      for (let i = 0; i < padLen; i += 64) {
        for (let j = 0; j < 16; j++) w[j] = view.getUint32(i + j * 4, false);
        for (let j = 16; j < 64; j++) {
          const s0 = ((w[j-15]>>>7)|(w[j-15]<<25))^((w[j-15]>>>18)|(w[j-15]<<14))^(w[j-15]>>>3);
          const s1 = ((w[j-2]>>>17)|(w[j-2]<<15))^((w[j-2]>>>19)|(w[j-2]<<13))^(w[j-2]>>>10);
          w[j] = (w[j-16]+s0+w[j-7]+s1)>>>0;
        }
        let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
        for (let j = 0; j < 64; j++) {
          const S1 = ((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
          const ch = (e&f)^(~e&g), t1 = (h+S1+ch+SHA256_K[j]+w[j])>>>0;
          const S0 = ((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
          const maj = (a&b)^(a&c)^(b&c), t2 = (S0+maj)>>>0;
          h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
        }
        h0=(h0+a)>>>0;h1=(h1+b)>>>0;h2=(h2+c)>>>0;h3=(h3+d)>>>0;h4=(h4+e)>>>0;h5=(h5+f)>>>0;h6=(h6+g)>>>0;h7=(h7+h)>>>0;
      }
      const result = new Uint8Array(32), rv = new DataView(result.buffer);
      rv.setUint32(0,h0,false);rv.setUint32(4,h1,false);rv.setUint32(8,h2,false);rv.setUint32(12,h3,false);
      rv.setUint32(16,h4,false);rv.setUint32(20,h5,false);rv.setUint32(24,h6,false);rv.setUint32(28,h7,false);
      return result;
    }
  };

  const RIPEMD160 = {
    hash: function(data) {
      if (typeof data === 'string') {
        const bytes = new Uint8Array(data.length / 2);
        for (let i = 0; i < data.length; i += 2) bytes[i/2] = parseInt(data.substr(i, 2), 16);
        data = bytes;
      }
      if (!(data instanceof Uint8Array)) data = new Uint8Array(data);
      const len = data.length, padLen = Math.ceil((len + 9) / 64) * 64;
      const padded = new Uint8Array(padLen);
      padded.set(data); padded[len] = 0x80;
      new DataView(padded.buffer).setUint32(padLen - 8, len * 8, true);
      let h0=0x67452301,h1=0xefcdab89,h2=0x98badcfe,h3=0x10325476,h4=0xc3d2e1f0;
      const r=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
      const rp=[5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
      const s=[11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
      const sp=[8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
      function f(j,x,y,z){if(j<16)return x^y^z;if(j<32)return(x&y)|(~x&z);if(j<48)return(x|~y)^z;if(j<64)return(x&z)|(y&~z);return x^(y|~z);}
      function K(j){return j<16?0:j<32?0x5a827999:j<48?0x6ed9eba1:j<64?0x8f1bbcdc:0xa953fd4e;}
      function Kp(j){return j<16?0x50a28be6:j<32?0x5c4dd124:j<48?0x6d703ef3:j<64?0x7a6d76e9:0;}
      function rotl(x,n){return((x<<n)|(x>>>(32-n)))>>>0;}
      for (let i = 0; i < padded.length; i += 64) {
        const X = [];
        for (let j = 0; j < 16; j++) X[j] = padded[i+j*4]|(padded[i+j*4+1]<<8)|(padded[i+j*4+2]<<16)|(padded[i+j*4+3]<<24);
        let al=h0,bl=h1,cl=h2,dl=h3,el=h4,ar=h0,br=h1,cr=h2,dr=h3,er=h4;
        for (let j = 0; j < 80; j++) {
          let tl = (al+f(j,bl,cl,dl)+X[r[j]]+K(j))>>>0;
          tl = (rotl(tl,s[j])+el)>>>0; al=el;el=dl;dl=rotl(cl,10);cl=bl;bl=tl;
          let tr = (ar+f(79-j,br,cr,dr)+X[rp[j]]+Kp(j))>>>0;
          tr = (rotl(tr,sp[j])+er)>>>0; ar=er;er=dr;dr=rotl(cr,10);cr=br;br=tr;
        }
        const t = (h1+cl+dr)>>>0;
        h1=(h2+dl+er)>>>0;h2=(h3+el+ar)>>>0;h3=(h4+al+br)>>>0;h4=(h0+bl+cr)>>>0;h0=t;
      }
      const result = new Uint8Array(20), view = new DataView(result.buffer);
      view.setUint32(0,h0,true);view.setUint32(4,h1,true);view.setUint32(8,h2,true);view.setUint32(12,h3,true);view.setUint32(16,h4,true);
      return result;
    }
  };

  function hmacSha256(key, data) {
    if (typeof key === 'string') { const b = new Uint8Array(key.length/2); for(let i=0;i<key.length;i+=2)b[i/2]=parseInt(key.substr(i,2),16); key=b; }
    if (typeof data === 'string') { const b = new Uint8Array(data.length/2); for(let i=0;i<data.length;i+=2)b[i/2]=parseInt(data.substr(i,2),16); data=b; }
    if (key.length > 64) key = SHA256.hash(key);
    const padded = new Uint8Array(64); padded.set(key);
    const ipad = new Uint8Array(64), opad = new Uint8Array(64);
    for (let i = 0; i < 64; i++) { ipad[i] = padded[i] ^ 0x36; opad[i] = padded[i] ^ 0x5c; }
    const inner = new Uint8Array(64 + data.length); inner.set(ipad); inner.set(data, 64);
    const innerHash = SHA256.hash(inner);
    const outer = new Uint8Array(64 + 32); outer.set(opad); outer.set(innerHash, 64);
    return SHA256.hash(outer);
  }

  function hash256(data) { return SHA256.hash(SHA256.hash(data)); }
  function hash160(data) { return RIPEMD160.hash(SHA256.hash(data)); }

  global.SHA256 = SHA256;
  global.RIPEMD160 = RIPEMD160;
  global.hmacSha256 = hmacSha256;
  global.hash256 = hash256;
  global.hash160 = hash160;
})(typeof window !== 'undefined' ? window : global);
