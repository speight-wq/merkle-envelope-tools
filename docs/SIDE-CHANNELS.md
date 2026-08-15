# Side-Channel Analysis — Browser-Based Offline Signer

## Executive Summary

Browser-based signing has inherent side-channel risks that cannot be fully mitigated without native code. This document catalogs known risks, their exploitability in an air-gapped context, and practical mitigations.

**Risk Rating:** MEDIUM in air-gapped deployment, HIGH if device ever reconnects.

---

## 1. Timing Side-Channels

### 1.1 BigInt Operations (CRITICAL)

**The Problem:**
JavaScript BigInt operations are not constant-time. The secp256k1 scalar multiplication leaks information about the private key through execution timing.

```javascript
// This leaks key bits through timing:
function pointMul(k, point) {
  let result = null;
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, point);  // Branch on key bit
    point = pointAdd(point, point);
    k >>= 1n;
  }
  return result;
}
```

**Attack Vector:**
- Local attacker with code execution could measure timing
- ~1-10 signatures may leak full key with precise measurements
- JavaScript JIT compilation makes timing variable but still exploitable

**Exploitability (Air-Gapped): LOW**
- Requires code execution on offline machine
- If attacker has code execution, they can just read the key directly
- Timing attack is harder than direct exfiltration

**Mitigations:**
```javascript
// Montgomery ladder - constant-time(ish) in JS
function pointMulConstantTime(k, point) {
  let R0 = null;
  let R1 = point;
  for (let i = 255n; i >= 0n; i--) {
    if ((k >> i) & 1n) {
      R0 = pointAdd(R0, R1);
      R1 = pointAdd(R1, R1);
    } else {
      R1 = pointAdd(R0, R1);
      R0 = pointAdd(R0, R0);
    }
  }
  return R0;
}
```

**Recommendation:** ACCEPT for air-gapped use. The threat model already assumes offline machine is trusted. Document the limitation.

---

### 1.2 Modular Inverse (HIGH)

**The Problem:**
Extended Euclidean algorithm has data-dependent loop count:

```javascript
function modInverse(a, m) {
  let [old_r, r] = [a, m];
  while (r !== 0n) {  // Loop count depends on input
    // ...
  }
}
```

**Attack Vector:**
- Number of iterations correlates with input value
- Combined with signature values, could leak key material

**Exploitability (Air-Gapped): LOW**
- Same reasoning as 1.1

**Mitigations:**
- Use Fermat's little theorem: `a^(-1) = a^(p-2) mod p`
- Fixed iteration count but much slower

**Recommendation:** ACCEPT. Document limitation.

---

### 1.3 Hash Function Timing (LOW)

**The Problem:**
SHA-256/RIPEMD-160 process data in blocks. Message length affects timing.

**Attack Vector:**
- Negligible for fixed-size inputs (32-byte keys, 32-byte hashes)
- Transaction data is already public

**Exploitability: NEGLIGIBLE**

**Recommendation:** NO ACTION needed.

---

## 2. Memory Side-Channels

### 2.1 JavaScript Heap Retention (HIGH)

**The Problem:**
JavaScript has no secure memory wipe. Setting a variable to `null` does not zero the underlying memory.

```javascript
let privateKey = BigInt('0x...');
// ... use key ...
privateKey = null;  // Memory NOT zeroed, just dereferenced
```

**Attack Vector:**
- Memory dump after signing could recover key
- Browser crash dumps may contain key
- Swap file could persist key to disk
- Cold boot attack on RAM

**Exploitability (Air-Gapped): MEDIUM**
- Requires physical access OR prior malware
- Key persists in memory until garbage collected
- GC timing is unpredictable

**Current Mitigation (Partial):**
```javascript
// We do this, but it's not sufficient:
currentKey = null;
currentPrivateKey = null;
```

**Better Mitigation:**
```javascript
// Attempt to overwrite (not guaranteed):
function clearBigInt(ref) {
  if (ref.buffer) {
    const arr = new Uint8Array(ref.buffer);
    crypto.getRandomValues(arr);  // Overwrite with random
  }
}

// Force GC hint (not guaranteed):
if (window.gc) window.gc();
```

**Best Mitigation:**
```javascript
// Use TypedArray instead of BigInt for sensitive ops:
const keyBytes = new Uint8Array(32);
// ... use keyBytes ...
crypto.getRandomValues(keyBytes);  // Secure overwrite
```

**Recommendation:** 
1. Add memory clearing attempts (partial mitigation)
2. Document that true secure wipe is impossible in JS
3. Recommend browser restart after signing
4. Recommend encrypted swap or swap disabled

---

### 2.2 String Interning (MEDIUM)

**The Problem:**
JavaScript engines may intern strings, keeping them in memory indefinitely.

```javascript
const wif = 'KwDiBf89QgGbj...';  // May be interned forever
```

**Attack Vector:**
- WIF string could persist in memory pool
- Hex representations of keys likewise

**Exploitability (Air-Gapped): MEDIUM**
- Same as 2.1

**Mitigation:**
```javascript
// Use Uint8Array for all sensitive data, never strings
const wifBytes = base58DecodeToBytes(wifInput.value);
wifInput.value = '';  // Clear input field
// Process wifBytes directly without string conversion
```

**Recommendation:** Refactor to minimize string usage for keys. Currently not implemented.

---

### 2.3 Browser Process Isolation (LOW)

**The Problem:**
Browser may share memory regions between tabs/processes. Spectre-class attacks could read cross-origin data.

**Attack Vector:**
- Spectre V1/V2 from another tab
- Requires malicious code in another tab

**Exploitability (Air-Gapped): NEGLIGIBLE**
- Air-gapped machine shouldn't have other tabs open
- No network to load malicious code

**Recommendation:** Document: "Close all other tabs before signing."

---

## 3. Clipboard Side-Channels

### 3.1 Clipboard History (CRITICAL)

**The Problem:**
Many OS/tools maintain clipboard history. Copying WIF or signed TX persists in history.

```javascript
navigator.clipboard.writeText(signedTxHex);  // Now in clipboard history
```

**Attack Vector:**
- Clipboard manager stores all copied text
- Persists across reboots in some tools
- Cloud-synced clipboards (Windows, macOS) - catastrophic if device reconnects

**Exploitability (Air-Gapped): HIGH if device reconnects**
- Clipboard history could sync when network restored
- Local clipboard history survives reboot

**Current Status:** We copy signed TX to clipboard. WIF is input (pasted), not copied.

**Mitigations:**
1. Clear clipboard after use:
```javascript
// Clear after 30 seconds:
setTimeout(() => {
  navigator.clipboard.writeText('');
}, 30000);
```

2. Warn user:
```html
<div class="warning">
  ⚠️ Clipboard cleared in 30 seconds. Paste your transaction now.
</div>
```

3. Document: "Disable clipboard history before use."

**Recommendation:** IMPLEMENT clipboard auto-clear. Add warning about clipboard history.

---

### 3.2 Clipboard Event Listeners (MEDIUM)

**The Problem:**
Malicious browser extensions can listen to clipboard events:

```javascript
// Malicious extension:
document.addEventListener('copy', (e) => {
  exfiltrate(e.clipboardData.getData('text'));
});
```

**Attack Vector:**
- Extension captures copied transaction
- Could also capture pasted WIF

**Exploitability (Air-Gapped): LOW**
- Requires malicious extension pre-installed
- Extension can't exfiltrate without network

**Mitigation:**
- Use private/incognito mode (extensions often disabled)
- Dedicated browser profile with no extensions

**Recommendation:** Document: "Use private browsing mode or browser with no extensions."

---

## 4. Browser Behavior Side-Channels

### 4.1 Autofill / Password Manager (HIGH)

**The Problem:**
Browser may offer to save input field contents.

```html
<input type="text" id="wif-input">  <!-- Browser may autofill/save -->
```

**Attack Vector:**
- WIF saved in browser password manager
- Synced to cloud if signed in

**Current Mitigation:**
```html
<input type="password" autocomplete="off" id="wif-input">
```

**Better Mitigation:**
```html
<input type="password" 
       autocomplete="off" 
       autocorrect="off" 
       autocapitalize="off" 
       spellcheck="false"
       data-lpignore="true"
       data-form-type="other">
```

**Recommendation:** IMPLEMENT all autofill prevention attributes.

---

### 4.2 Browser History / Cache (LOW)

**The Problem:**
- `file://` URLs appear in browser history
- Local storage could cache data

**Attack Vector:**
- History reveals tool was used
- Minimal information leakage

**Current Mitigation:**
- No localStorage usage
- No sensitive data in URL

**Recommendation:** NO ACTION. Already handled.

---

### 4.3 Crash Reports / Telemetry (MEDIUM)

**The Problem:**
Browser crash during signing could:
- Upload memory dump to vendor
- Include console.log output
- Capture DOM state with key visible

**Attack Vector:**
- Crash dump includes private key
- Telemetry phones home when network restored

**Exploitability (Air-Gapped): MEDIUM if device reconnects**

**Mitigations:**
1. Disable crash reporting in browser settings
2. Use hardened browser (LibreWolf, Tor Browser)
3. Never reconnect device to network

**Recommendation:** Document browser hardening steps.

---

### 4.4 Developer Tools (LOW)

**The Problem:**
If DevTools are open, console may log sensitive data:

```javascript
console.log('Signing with key:', privateKey);  // We don't do this
```

**Current Status:** We log non-sensitive data only (txid, sizes, etc.)

**Recommendation:** VERIFY no sensitive logging. Already OK.

---

## 5. QR Code Side-Channels

> **Note:** The current `signer.html` generates **no QR code** — the signed transaction is delivered via clipboard copy and file download. This section is retained as forward-looking analysis in case QR output is added later.

### 5.1 Screen Capture (MEDIUM)

**The Problem:**
QR code displayed on screen could be:
- Captured by screen recording malware
- Photographed by nearby camera
- Visible in screen sharing (shouldn't happen air-gapped)

**Attack Vector:**
- Signed TX captured (not catastrophic - TX is meant to be broadcast)
- If QR contained WIF (we don't do this), catastrophic

**Current Status:** QR only contains signed TX, not private key.

**Recommendation:** NO ACTION. Signed TX is not sensitive.

---

### 5.2 QR Scanner App Logging (LOW)

**The Problem:**
Phone QR scanner app might log scanned data.

**Attack Vector:**
- Scanner app stores signed TX
- Not sensitive (TX is broadcast anyway)

**Recommendation:** NO ACTION. Acceptable risk.

---

## 6. Implementation Checklist

*(Reconciled against the current `signer.html` — ✓ = verified present, ◐ = partial, ✗ = not present.)*

### Already Implemented ✓ (verified in signer.html)
- [x] Password field type for WIF input (`type="password"`)
- [x] No logging of any kind — **zero** `console.*` calls in signer.html
- [x] No localStorage / sessionStorage usage
- [x] `autocomplete="off"` on the WIF input
- [x] Private-key field cleared after signing (`private-key.value = ''`) — as far as JS allows (see §2.1 memory caveat)
- [x] Signed TX delivered via clipboard copy + file download. **signer.html generates no QR code**, so §5 (QR side-channels) is precautionary/hypothetical for the current build. WIF is pasted (input), never copied.

### Partially Implemented / Should Complete

**P0 — Critical:**
- [◐] Autofill-prevention attributes — `autocomplete="off"` is present; `autocorrect`, `autocapitalize`, `spellcheck="false"`, `data-lpignore`, `data-form-type="other"` are still missing.
- [✗] Clipboard auto-clear after 30–60 s — NOT done. The `setTimeout` on the copy button only resets its label, it does not clear the clipboard. Severity is lowered by the fact that **only the signed TX is ever copied** (non-sensitive); the WIF never reaches the clipboard.

**P1 — Important:**
- [x] Clear the sensitive field after signing — private key **is** cleared. (Destination/amount are not cleared post-sign, but hold no secrets.)
- [x] "Browser Hardening" guidance in docs — present (see §7, Hardened Usage Guide).
- [✗] In-UI warning about clipboard history — NOT done (low priority: only the non-sensitive signed TX is copied).

**P2 — Nice to Have:**
- [✗] Attempt memory overwrite (TypedArray approach)
- [✗] "Clear & Close" button that wipes all fields in one action (fields are cleared individually today)
- [x] Browser-restart / shutdown recommendation after signing — present (see §7, After Signing).

### Won't Fix (Documented)
- [ ] Constant-time BigInt operations (infeasible in JS)
- [ ] True secure memory wipe (impossible in JS)
- [ ] GC-forced memory clearing (unreliable)

### Note on BUMP/BEEF modules (v2.2.0)
`lib/bump.js` and `lib/beef.js` are **not loaded by signer.html** and never touch key material — they are used by the generator (online) and the verifier/explorer (offline, no keys). They add **no side-channel surface to the signing operation**. They remain in scope for file-integrity checksums (see the README hash table).

---

## 7. Hardened Usage Guide

For high-value signing, users should:

### Before Signing
1. Use dedicated device that will NEVER reconnect to network
2. Boot from live USB (Tails, etc.) — RAM clears on shutdown
3. Disable swap: `sudo swapoff -a`
4. Disable crash reporting in browser
5. Use private/incognito mode
6. Close all other tabs
7. Disable clipboard history

### During Signing
1. Verify destination address character-by-character
2. Do not leave key on screen longer than necessary
3. Ensure no cameras can see screen

### After Signing
1. Clear all input fields
2. Close browser completely
3. If live USB: shut down (RAM cleared)
4. If persistent OS: restart computer
5. Never reconnect device to network

---

## 8. Comparison: Browser vs Native vs Hardware

| Risk | Browser JS | Native App | Hardware Wallet |
|------|------------|------------|-----------------|
| Timing side-channel | HIGH | LOW | NONE |
| Memory persistence | HIGH | MEDIUM | NONE |
| Clipboard leakage | HIGH | MEDIUM | NONE |
| Supply chain | MEDIUM | HIGH | LOW |
| Auditability | HIGH | MEDIUM | LOW |
| Air-gap ease | HIGH | MEDIUM | HIGH |

**Conclusion:** Browser-based signing trades cryptographic robustness for auditability and simplicity. Acceptable for moderate values with proper precautions. For high-value storage, use hardware wallet.

---

## 9. Summary

| Category | Risk Level | Mitigation Status |
|----------|------------|-------------------|
| Timing attacks | LOW (air-gapped) | Documented |
| Memory retention | MEDIUM | Partial |
| Clipboard leakage | LOW (WIF never copied; only signed TX) | Auto-clear still recommended |
| Browser autofill | MEDIUM | Partial (`autocomplete="off"` only) |
| Crash telemetry | MEDIUM | Documented |

**Overall:** The tool is appropriate for air-gapped use with documented limitations. The private key is never copied to the clipboard, so the primary residual risk is **memory persistence** if the device is ever reconnected to a network; the signed-TX clipboard entry is at most a minor privacy leak, not a key-theft vector.
