# Transaction Processing Checks

Applies to: transaction validation, execution, fee/gas handling, mempool.
Also load `common.md` (INT-01, INT-02, INT-03, RACE-01 apply here).

---

### TX-01: Checked Arithmetic Return Value Discarded

- **Severity**: High
- **CWE**: CWE-190 — Integer Overflow or Wraparound

**Problem**
`Math.addExact()` / `LongMath.checkedAdd()` protect against overflow only when their return value is used. Calling them as a statement (discarding the return value) creates a false sense of security: the exception fires if overflow occurs, but the subsequent unchecked expression is still applied. See also `INT-03` in `common.md` for the pattern; this check focuses on the transaction execution code specifically.

**Bad Example**
```java
// validate() — check is performed but result thrown away
Math.addExact(balance, amount);  // result discarded

// execute() — unchecked arithmetic used for the actual update
account.setBalance(balance + amount);  // ❌ can overflow
```

**Good Example**
```java
// Use the checked result for the actual update
long newBalance = Math.addExact(balance, amount);
account.setBalance(newBalance);
```

---

### TX-02: Governance Parameter Controls Security-Critical Math Mode

- **Severity**: Critical
- **CWE**: CWE-284 — Improper Access Control
- **OWASP**: A04:2021 — Insecure Design

**Problem**
Some blockchains expose a governance proposal mechanism that lets token holders vote to change runtime parameters. If a parameter controls whether arithmetic uses strict (deterministic) or lenient (platform-dependent) math, then a governance attack — accumulating enough voting power — can disable safety-critical invariants. Once disabled, arithmetic inconsistencies between nodes can cause state divergence.

**Bad Example**
```java
// Runtime selects math mode based on a governable on-chain flag
public void init(Config cfg) {
    if (cfg.getBoolean("strictMath")) {
        math = new StrictMath();
    } else {
        math = new NativeMath();   // ❌ platform-dependent, governable
    }
}
```

**Good Example**
```java
// Security-critical behavior must not be runtime-governable
public void init() {
    math = new StrictMath();  // unconditional
    // Remove strictMath from the governance parameter registry
}
```

---

### TX-03: Transaction Signature Verification Not on All Entry Points

- **Severity**: Critical
- **CWE**: CWE-347 — Improper Verification of Cryptographic Signature
- **OWASP**: A02:2021 — Cryptographic Failures

**Problem**
A transaction must have its signature verified at every entry point that accepts it: HTTP API, gRPC, P2P gossip, and any fast/internal path. If a new code path is added (e.g., a fast-path for internal transactions) without calling the signature verification function, unsigned or forged transactions can be executed.

**Bad Example**
```java
// Standard path — correct
public void submit(Tx tx) throws ValidationException {
    tx.verify();
    execute(tx);
}

// Fast path — added later, verification forgotten
public void submitFast(Tx tx) {
    // ❌ No signature verification — assumes caller already did it
    execute(tx);
}
```

**Good Example**
```java
// Defense-in-depth: verify at every public entry point unconditionally
public void submitFast(Tx tx) throws ValidationException {
    tx.verify();   // ✅ always verify, even on "trusted" paths
    execute(tx);
}
```

---

### TX-04: Mempool (Pending Transaction Queue) Without Size Bound

- **Severity**: High
- **CWE**: CWE-770 — Allocation of Resources Without Limits or Throttling
- **OWASP**: A05:2021 — Security Misconfiguration

**Problem**
An unbounded mempool allows an attacker to flood the node with valid but low-fee transactions, growing the queue until heap memory is exhausted and the node crashes. The attack is cheap because valid transactions require no special privilege — only a small, recoverable transaction fee.

**Bad Example**
```java
// Mempool backed by an unbounded queue
private final Queue<Tx> queue = new LinkedBlockingQueue<>();
// or: new ConcurrentLinkedQueue<>()
// Config parameter maxSize exists but is never applied here
```

**Good Example**
```java
private final int maxSize;  // loaded from config

public boolean add(Tx tx) {
    if (queue.size() >= maxSize) {
        // Evict lowest-fee transaction or reject new one
        if (tx.fee() <= minFee()) {
            return false;  // reject
        }
        queue.poll();  // evict cheapest
    }
    return queue.offer(tx);
}
```

---

### TX-05: Multi-Signature Weight Threshold Computed with Integer Overflow Risk

- **Severity**: High
- **CWE**: CWE-190 — Integer Overflow or Wraparound

**Problem**
Multi-signature schemes aggregate weights from multiple signers. If individual weights are large and accumulated with unchecked `int` addition, the total can wrap through `Integer.MIN_VALUE` and back to a large positive number. For example, with two signers each having `weight = Integer.MAX_VALUE`: after the first, `total = MAX_VALUE`; after the second, `total = -2` (negative, fails the check); with a third signer, `total = MAX_VALUE - 2` (large positive, passes the check). The attacker can thus craft a signer set where the accumulated total wraps to a value that satisfies `total >= threshold`, authorizing a transaction that should have been rejected.

**Bad Example**
```java
int total = 0;
for (Sig s : sigs) {
    if (verify(s, tx)) {
        total += s.weight();   // ❌ unchecked int addition — wraps
    }
}
if (total >= threshold) {  // total may have wrapped to an unexpected positive value
    authorize(tx);
}
```

**Good Example**
```java
long total = 0;
for (Sig s : sigs) {
    if (verify(s, tx)) {
        try {
            total = Math.addExact(total, s.weight());
        } catch (ArithmeticException e) {
            throw new ValidationException("Signature weight overflow");
        }
    }
}
if (total >= threshold) {
    authorize(tx);
}
```
