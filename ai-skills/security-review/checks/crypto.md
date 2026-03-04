# Cryptography Checks

Applies to: key management, signature generation/verification, hash functions, ZK proof verification.

---

### CRY-01: Non-Deterministic Nonce (k) in Signature Generation

- **Severity**: Critical
- **CWE**: CWE-338 — Use of Cryptographically Weak Pseudo-Random Number Generator
- **OWASP**: A02:2021 — Cryptographic Failures

**Problem**
ECDSA and its variants (SM2, secp256k1, Ed25519 variants) require a unique, unpredictable nonce `k` for each signing operation. If `k` is generated from a random source that can ever produce the same value for two different messages — due to weak entropy, PRNG seed reuse, process fork, or bug — an observer who sees both signatures can solve a linear equation to recover the private key (the same principle as the 2013 PlayStation 3 root key leak and the 2013 Bitcoin Android wallet attack).

RFC 6979 defines a deterministic algorithm that derives `k` from the private key and message hash via HMAC, guaranteeing uniqueness without relying on a random source.

**Bad Example**
```java
// Non-deterministic k: relies on SecureRandom
DSAKCalculator kCalculator = new RandomDSAKCalculator();
ECDSASigner signer = new ECDSASigner(kCalculator);
signer.init(true, privateKeyParams);
BigInteger[] sig = signer.generateSignature(messageHash);
// If SecureRandom ever reuses a seed or two calls see the same output → private key recoverable
```

**Good Example**
```java
// RFC 6979 deterministic k: derived from privkey + message hash via HMAC
// Same (privkey, message) → always same k → never reused for different messages
DSAKCalculator kCalculator = new HMacDSAKCalculator(new SHA256Digest());
// For SM2: new HMacDSAKCalculator(new SM3Digest())
ECDSASigner signer = new ECDSASigner(kCalculator);
signer.init(true, new ECPrivateKeyParameters(privateKey, curveParams));
BigInteger[] sig = signer.generateSignature(messageHash);
```

---

### CRY-02: Elliptic Curve Point Not Validated Before Use

- **Severity**: High
- **CWE**: CWE-20 — Improper Input Validation
- **OWASP**: A02:2021 — Cryptographic Failures

**Problem**
Cryptographic operations (pairing, scalar multiplication, proof verification) require all input points to be valid points on the expected curve, in the expected subgroup, and not the point at infinity. An "invalid curve attack" supplies a point on a different curve with a small group order; scalar multiplication leaks bits of the private key through the result. A subgroup attack supplies a low-order point to make the pairing or proof check trivially succeed.

**Bad Example**
```java
// BN128 / G1 point from user-supplied bytes — no validation
G1Point point = G1Point.fromBytes(inputData);
// ❌ No check that point.isOnCurve() or point.isInSubgroup()
BigInteger result = pairingCheck(point, g2Point);
// Attacker supplies a low-order point → pairing yields 1 trivially → proof accepted
```

**Good Example**
```java
G1Point point = G1Point.fromBytes(inputData);
if (point == null) {
    return FAILURE;  // decoding failed
}
if (!point.isOnCurve()) {
    return FAILURE;  // not on the expected curve
}
if (point.isInfinity()) {
    return FAILURE;  // point at infinity not allowed as input
}
// For pairing-based ZK: also check prime-order subgroup membership
if (!point.isInSubgroup()) {
    return FAILURE;
}
BigInteger result = pairingCheck(point, g2Point);
```

---

### CRY-03: Signature Malleability Not Rejected

- **Severity**: Medium
- **CWE**: CWE-347 — Improper Verification of Cryptographic Signature
- **OWASP**: A02:2021 — Cryptographic Failures

**Problem**
For every valid ECDSA signature `(r, s)` over secp256k1, there exists an equally valid signature `(r, n − s)` (where `n` is the curve order). Without normalizing `s` to the lower half of the range (`s ≤ n/2`), the same transaction can be re-signed by anyone without knowing the private key. This produces a second valid transaction with a different transaction ID, enabling txid malleability — it breaks exchange tracking, replay protection assumptions, and may confuse off-chain systems that check by txid.

**Bad Example**
```java
ECDSASignature sig = ECDSASignature.fromDER(rawSignature);
// ❌ No check for high-s — accepts both (r,s) and (r, n-s) as valid
if (!publicKey.verify(messageHash, sig)) {
    throw new InvalidSignatureException();
}
```

**Good Example**
```java
ECDSASignature sig = ECDSASignature.fromDER(rawSignature);
// ✅ Reject high-s: only the canonical low-s form is accepted
if (sig.s.compareTo(HALF_CURVE_ORDER) > 0) {
    throw new InvalidSignatureException("Non-canonical signature (high s value)");
}
if (!publicKey.verify(messageHash, sig)) {
    throw new InvalidSignatureException("Signature verification failed");
}
```

---

### CRY-04: SecureRandom Instantiated per Signing Operation

- **Severity**: Medium
- **CWE**: CWE-338 — Use of Cryptographically Weak Pseudo-Random Number Generator

**Problem**
Creating `new SecureRandom()` for each signing or key-generation call is expensive (entropy pool seeding on JVM startup) and, in constrained environments (containers, early-boot, some cloud VMs), can block or produce weakly seeded output. The correct pattern is to share a single pre-seeded `SecureRandom` instance. Even better, eliminate randomness from signing entirely by using deterministic nonce derivation (CRY-01).

**Bad Example**
```java
public byte[] signTransaction(byte[] txHash, BigInteger privateKey) {
    SecureRandom random = new SecureRandom();   // ❌ new instance per call
    kCalculator.init(curveOrder, random);
    return sign(txHash, privateKey);
}
```

**Good Example**
```java
// Option A: Shared instance (thread-safe after initial seeding)
private static final SecureRandom SECURE_RANDOM = new SecureRandom();

// Option B (preferred): Deterministic nonce — no SecureRandom needed
private static final HMacDSAKCalculator K_CALC = new HMacDSAKCalculator(new SHA256Digest());

public byte[] signTransaction(byte[] txHash, BigInteger privateKey) {
    K_CALC.init(curveOrder, privateKey, txHash);  // deterministic, no random needed
    return sign(txHash, privateKey);
}
```
