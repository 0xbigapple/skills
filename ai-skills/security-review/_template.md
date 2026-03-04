# Check Item Template

Use this file when adding a new check to any module file in `checks/`.

---

## Checklist Before Writing

1. Look up the next available ID in `_index.md` — never reuse an existing ID.
2. Verify the check is not a duplicate of an existing item (search by CWE and symptom).
3. Ensure the Bad/Good Examples use **generic** class names, not project-specific names.
4. The check must apply to **any** Java blockchain node, not a specific codebase.

---

## Template

Copy and paste this block into the target module file:

```
### PREFIX-NN: Title (Imperative, 5–10 Words)

- **Severity**: Critical / High / Medium / Low
- **CWE**: CWE-NNN — [CWE Name]
- **OWASP**: A0N:2021 — [Category]  *(omit this line if no clear mapping)*

**Problem**
One to two paragraphs. State: what is the vulnerable pattern, why it arises in blockchain Java code,
and what an attacker can achieve (fund theft, consensus fork, DoS, auth bypass, RCE, data corruption).
Be concrete: name the exploitable invariant and the consequence.

**Bad Example**
​```java
// Generic Java — placeholder names only (e.g. ConsensusEngine, BlockValidator, PeerHandler)
// Show exactly the vulnerable pattern; include a comment explaining the exploit path
​```

**Good Example**
​```java
// Show the minimal correct fix — do not rewrite surrounding logic
// Add a ✅ comment on the line that is the key change
​```
```

---

## Field Reference

### ID Prefix

| File | Prefix(es) | Example |
|------|-----------|---------|
| `common.md` | `INT`, `RACE`, `OOM`, `DESER`, `ERR`, `NET` | INT-05 |
| `consensus.md` | `CON` | CON-07 |
| `p2p.md` | `P2P` | P2P-06 |
| `vm.md` | `VM` | VM-06 |
| `transaction.md` | `TX` | TX-06 |
| `api.md` | `API` | API-06 |
| `crypto.md` | `CRY` | CRY-05 |
| `storage.md` | `DB` | DB-06 |
| `platform.md` | `PLT` | PLT-05 |
| `config.md` | `CFG` | CFG-06 |

### Severity Decision Tree

```
Does it allow fund theft, RCE, consensus split, or full-node crash
with no prerequisites beyond network access?
  → Critical

Does it require specific conditions but still cause significant impact:
DoS, data corruption, auth bypass, private key exposure?
  → High

Does it require chaining multiple conditions, or has only partial
impact when exploited in isolation?
  → Medium

Is it a defense-in-depth gap with minimal standalone exploitability?
  → Low
```

### CWE Quick Picks

Most checks in this skill map to one of these CWEs.

| CWE | Name | Typical Check |
|-----|------|---------------|
| CWE-20 | Improper Input Validation | payload size, curve point, arch detection |
| CWE-190 | Integer Overflow or Wraparound | balance, slot index, gas arithmetic |
| CWE-193 | Off-by-one Error | call depth, BFT quorum threshold |
| CWE-209 | Error Message Contains Sensitive Info | stack trace in API response |
| CWE-284 | Improper Access Control | static call, governance flag |
| CWE-290 | Auth Bypass by Spoofing | X-Forwarded-For header |
| CWE-306 | Missing Authentication for Critical Function | API bound to 0.0.0.0 |
| CWE-312 | Cleartext Storage of Sensitive Info | private key in config |
| CWE-338 | Weak PRNG | non-RFC6979 nonce, per-call SecureRandom |
| CWE-347 | Improper Sig Verification | state change before verify, malleability |
| CWE-362 | Improper Synchronization | non-volatile field, TOCTTOU |
| CWE-367 | TOCTOU Race Condition | check-then-act outside lock |
| CWE-400 | Uncontrolled Resource Consumption | body size, fsync disabled |
| CWE-502 | Deserialization of Untrusted Data | FastJSON autoType, ObjectInputStream |
| CWE-693 | Protection Mechanism Failure | double-sign without slashing |
| CWE-770 | Allocation Without Limits | mempool, cache, filters, rate limiter |
| CWE-923 | Improper Restriction of Comm Channel | eclipse attack, no subnet diversity |
| CWE-1339 | Insufficient Precision | float in consensus math, cross-platform pow() |

### OWASP Top 10 (2021) Quick Picks

| Code | Category | Typical Check |
|------|----------|---------------|
| A01:2021 | Broken Access Control | static call opcode |
| A02:2021 | Cryptographic Failures | key storage, sig verify, ECDSA nonce |
| A03:2021 | Injection | unvalidated payload processed as command |
| A04:2021 | Insecure Design | slashing absent, float in consensus, governance |
| A05:2021 | Security Misconfiguration | rate limit off, fsync off, no API size limit |
| A07:2021 | ID and Auth Failures | API on 0.0.0.0, IP spoofing |
| A08:2021 | Software & Data Integrity Failures | deserialization, autoType |

---

## After Adding a Check

1. Append the new entry to `_index.md` (maintain severity order within the table).
2. Update the **Next Available IDs** table in `_index.md`.
3. If the check applies across multiple modules, add a row to the **Common Checks Cross-Reference** table.
