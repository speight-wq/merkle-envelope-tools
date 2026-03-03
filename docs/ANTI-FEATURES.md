# Anti-Features: What This Tool Should Never Do

## Philosophy

This tool has a narrow purpose: **offline transaction signing with SPV verification**. Feature creep is the enemy of security. Every addition expands attack surface, increases audit burden, and dilutes focus.

This document lists features that should **never** be added, even if requested.

---

## 1. Private Key Generation

### Request:
> "Add a button to generate a new private key"

### Why Never:

| Risk | Severity |
|------|----------|
| Browser RNG may be weak | CRITICAL |
| No way to verify entropy quality | CRITICAL |
| Users will trust generated keys | CRITICAL |
| Encourages browser as key storage | HIGH |

**The Problem:**

JavaScript's `crypto.getRandomValues()` is generally secure, but:
- Cannot audit the browser's RNG implementation
- Cannot verify hardware RNG is being used
- Cannot detect VM/container entropy starvation
- No way to add user entropy (mouse movements, etc.) reliably

**What Happens When This Goes Wrong:**

Weak RNG → predictable keys → funds stolen. This has happened:
- Android SecureRandom bug (2013) — $5.7M stolen
- Numerous JavaScript wallet compromises

**The Right Answer:**

Generate keys using dedicated tools:
- Hardware wallet
- `openssl rand -hex 32` on air-gapped Linux
- Dice + BIP39 wordlist
- Dedicated key generation software with audited RNG

**This tool consumes keys. It does not create them.**

---

## 2. Seed Phrase / BIP39 Support

### Request:
> "Let me enter my 12/24 word seed phrase"

### Why Never:

| Risk | Severity |
|------|----------|
| Seed phrase = all keys | CRITICAL |
| Single compromise = total loss | CRITICAL |
| Encourages typing seeds into browsers | CRITICAL |
| Derivation path confusion | HIGH |

**The Problem:**

A seed phrase derives **unlimited** private keys. Exposing it to a browser—even offline—risks:
- Memory persistence (seed stays in RAM)
- Typos creating wrong keys
- Clipboard capture of seed
- User confusion about derivation paths

**Contrast with WIF:**

WIF exposes **one** key. If compromised, one address is at risk. Seed phrase compromise = everything.

**The Right Answer:**

Export individual WIF keys from your wallet for the specific UTXO you're spending. Never type a seed phrase into a browser.

**This tool accepts single keys. Never master secrets.**

---

## 3. Address Book / Contact Storage

### Request:
> "Save my frequently used addresses"

### Why Never:

| Risk | Severity |
|------|----------|
| Requires persistent storage | HIGH |
| localStorage is not secure | HIGH |
| Creates exfiltration target | MEDIUM |
| Stale addresses cause losses | MEDIUM |

**The Problem:**

Any persistent storage in a browser:
- Can be read by other scripts (XSS)
- Syncs to cloud in some browsers
- Persists after "clearing" in some cases
- Creates state that can be corrupted

**Address Reuse is Bad Anyway:**

Storing addresses encourages reuse. Bitcoin privacy and security improve with fresh addresses per transaction.

**The Right Answer:**

Copy-paste addresses for each transaction. Verify character-by-character every time.

**This tool is stateless. Every session starts clean.**

---

## 4. Transaction History

### Request:
> "Show my past transactions"

### Why Never:

| Risk | Severity |
|------|----------|
| Requires persistent storage | HIGH |
| Links identity across sessions | HIGH |
| Creates forensic evidence | MEDIUM |
| Requires network to fetch | MEDIUM |

**The Problem:**

Transaction history:
- Must be stored (see #3)
- Or fetched from network (defeats offline purpose)
- Links all your addresses together
- Leaves evidence on device

**The Right Answer:**

Use a block explorer for history. Keep the signing tool amnesiac.

**This tool forgets everything when closed.**

---

## 5. Network Broadcasting

### Request:
> "Add a broadcast button to submit the transaction"

### Why Never:

| Risk | Severity |
|------|----------|
| Destroys air-gap model | CRITICAL |
| Encourages online signing | CRITICAL |
| Network code = attack surface | HIGH |
| Single point of broadcast failure | MEDIUM |

**The Problem:**

The entire security model assumes:
```
OFFLINE: Private key + Signing
ONLINE:  Everything else
```

Adding broadcast means the signing tool needs network access. Users will:
- Enable network "just for broadcast"
- Forget to disable it
- Eventually sign while online

**The Right Answer:**

Signed transactions transfer via QR/USB/file to a separate online device. Broadcast happens elsewhere.

**This tool never touches the network. That's the point.**

---

## 6. Multiple Input Transactions

### Request:
> "Let me consolidate multiple UTXOs in one transaction"

### Why Probably Never:

| Risk | Severity |
|------|----------|
| Links addresses together | HIGH |
| Complexity increases bugs | MEDIUM |
| Multiple envelopes to verify | MEDIUM |
| UX confusion | MEDIUM |

**The Nuance:**

This one is debatable. Multi-input is genuinely useful for consolidation. But:

- Privacy: Combining inputs proves common ownership
- Complexity: Must verify multiple envelopes
- UX: Which input pays fee? How to display?
- Attack surface: More parsing, more edge cases

**If Ever Added:**

- Separate "advanced" tool
- Explicit privacy warnings
- Each input independently verified
- Never in the main signer

**Current stance: Out of scope. Use multiple transactions.**

---

## 7. Custom Scripts / OP_RETURN

### Request:
> "Let me add OP_RETURN data to my transaction"

### Why Never:

| Risk | Severity |
|------|----------|
| Script validation is hard | HIGH |
| Edge cases in encoding | HIGH |
| Users will embed sensitive data | MEDIUM |
| Expands attack surface | MEDIUM |

**The Problem:**

OP_RETURN seems simple but:
- Data must be properly encoded
- Size limits vary by node policy
- Users might embed private data on public chain
- Opens door to "just add P2SH support"

**Scope Creep Path:**
```
OP_RETURN → P2SH → multisig → timelocks → full scripting
```

Each step adds complexity and audit burden.

**The Right Answer:**

This tool does P2PKH. One input, one output, change back to source. That's it.

**This tool is deliberately limited. Simplicity is security.**

---

## 8. Fee Estimation from Network

### Request:
> "Fetch current fee rates from the network"

### Why Never:

| Risk | Severity |
|------|----------|
| Requires network access | HIGH |
| Defeats offline signing | HIGH |
| Fee estimation is complex | MEDIUM |
| API dependency | MEDIUM |

**The Problem:**

Fee estimation needs:
- Network access (breaks air-gap)
- Mempool analysis (complex)
- API trust (what if manipulated?)

BSV fees are predictable anyway: 1 sat/byte works.

**The Right Answer:**

Manual fee entry with presets. User takes responsibility.

**This tool doesn't know what the network is doing. By design.**

---

## 9. Price Conversion / Fiat Display

### Request:
> "Show the USD value of my transaction"

### Why Never:

| Risk | Severity |
|------|----------|
| Requires price feed (network) | HIGH |
| Prices are manipulable | MEDIUM |
| Distracts from sat verification | MEDIUM |
| Scope creep | LOW |

**The Problem:**

Showing "$X USD" requires:
- Network access for price
- Trust in price source
- Handling of stale prices

Users might verify "$100" looks right while missing that sat amount is wrong.

**The Right Answer:**

Display satoshis. Users convert mentally or separately.

**This tool speaks satoshis. The unit of the protocol.**

---

## 10. Wallet Import (xpub/xprv)

### Request:
> "Import my wallet's extended public key to find UTXOs"

### Why Never:

| Risk | Severity |
|------|----------|
| xprv = all keys (see #2) | CRITICAL |
| xpub requires derivation logic | HIGH |
| Gap limit problems | MEDIUM |
| Complexity explosion | HIGH |

**The Problem:**

HD wallet support means:
- BIP32 derivation implementation
- BIP44/49/84 path handling
- Gap limit scanning
- State management (which addresses used?)

This transforms a simple signer into a full wallet.

**The Right Answer:**

Export specific WIF for specific UTXO. Use your wallet software for discovery.

**This tool is a signer, not a wallet.**

---

## 11. QR Code Scanning (Camera Access)

### Request:
> "Let me scan a QR code with my camera to input data"

### Why Never:

| Risk | Severity |
|------|----------|
| Camera permission = surveillance risk | HIGH |
| Camera APIs are complex | MEDIUM |
| Malicious QR injection | MEDIUM |
| Privacy implications | MEDIUM |

**The Problem:**

Camera access:
- Requires permission grant (user learns to click "allow")
- Camera could be activated maliciously
- QR content must be parsed (attack vector)
- Works poorly in file:// context anyway

**The Right Answer:**

QR codes are for **output** (signed TX). Input is paste or file upload.

**This tool outputs QR. It doesn't read them.**

---

## 12. Encrypted Key Storage

### Request:
> "Let me save my encrypted key for next time"

### Why Never:

| Risk | Severity |
|------|----------|
| Browser storage is insecure | CRITICAL |
| Password prompts train bad habits | HIGH |
| Users will use weak passwords | HIGH |
| Creates persistent target | HIGH |

**The Problem:**

"Encrypted storage" in a browser:
- localStorage is accessible to scripts
- Encryption key must be derived from password
- Password entry in browser is observable
- Encrypted blob is exfiltration target

**The Right Answer:**

Encrypted keys belong in:
- Hardware wallets
- OS keychain
- Dedicated password managers
- Encrypted files (GPG)

Not browsers.

**This tool holds keys transiently. Never persistently.**

---

## 13. Automatic UTXO Selection

### Request:
> "Automatically pick which UTXO to spend"

### Why Never:

| Risk | Severity |
|------|----------|
| Requires network lookup | HIGH |
| Selection algorithm is complex | MEDIUM |
| Privacy implications | HIGH |
| User should choose consciously | MEDIUM |

**The Problem:**

UTXO selection involves:
- Fetching all UTXOs (network)
- Privacy-aware selection (avoid linking)
- Fee optimization
- Change handling

This is wallet logic, not signer logic.

**The Right Answer:**

User provides specific envelope for specific UTXO. Conscious choice.

**This tool signs what you give it. It doesn't choose for you.**

---

## Summary: The Minimalist Principle

### What This Tool Does:
1. Verify SPV envelope (offline)
2. Sign transaction (offline)
3. Output signed TX (QR/file/clipboard)

### What This Tool Will Never Do:
- Generate keys
- Store anything
- Touch the network
- Become a wallet
- Handle complex scripts
- Make decisions for users

### The Test:

Before adding any feature, ask:

1. **Does it require network?** → No
2. **Does it require storage?** → No
3. **Does it handle master secrets?** → No
4. **Does it increase attack surface significantly?** → Reject
5. **Does it duplicate wallet functionality?** → Reject
6. **Can a user reasonably do this elsewhere?** → They should

---

## Requests to Redirect

| User Wants | Redirect To |
|------------|-------------|
| Generate keys | Hardware wallet, `openssl`, dice |
| Store keys | Password manager, hardware wallet |
| See history | Block explorer |
| Broadcast | WhatsOnChain, own node |
| HD wallet | Electrum, Sparrow, hardware wallet |
| Multi-input | Multiple transactions, or different tool |
| Price info | CoinGecko, exchange |

---

## Final Word

> "Perfection is achieved not when there is nothing more to add, but when there is nothing left to take away."
> — Antoine de Saint-Exupéry

This tool is intentionally incomplete. That's not a bug. That's the security model.

Every feature not present is an attack that cannot happen.
