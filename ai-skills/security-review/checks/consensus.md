# Consensus Checks — BFT / DPoS / PoS Consensus Layer

Applies to: consensus engine, validator scheduling, finality logic.
Also load `common.md` (INT-01, INT-02, INT-04, RACE-01, RACE-02 all apply here).

---

### CON-01: State Mutation Before Signature Verification

- **Severity**: Critical
- **CWE**: CWE-347 — Improper Verification of Cryptographic Signature
- **OWASP**: A02:2021 — Cryptographic Failures

**Problem**
A consensus message (PBFT PREPARE, Tendermint PREVOTE, HotStuff VOTE, etc.) must be fully authenticated before it has any effect on node state. If the code inserts a message into a tracking collection or calls downstream handlers before verifying the sender's signature, an attacker can pollute consensus state with arbitrary messages at zero cost — no valid private key required.

**Bad Example**
```java
public void onMessage(Msg msg) {
    // ❌ Message recorded before authentication
    seen.put(msg.round(), msg);

    try {
        verify(msg.key(), msg.data(), msg.sig());
    } catch (SignatureException e) {
        log.warn("bad signature from {}", msg.sender());
        // ❌ Falls through — downstream handler processes unauthenticated message
    }
    process(msg);
}
```

**Good Example**
```java
public void onMessage(Msg msg) {
    // ✅ Authenticate first; discard on failure
    try {
        verify(msg.key(), msg.data(), msg.sig());
    } catch (SignatureException e) {
        log.warn("Rejected message with invalid signature from {}", msg.sender());
        return;
    }
    seen.put(msg.round(), msg);
    process(msg);
}
```

---

### CON-02: Equivocation (Double-Sign) Without Slashing

- **Severity**: Critical
- **CWE**: CWE-693 — Protection Mechanism Failure
- **OWASP**: A04:2021 — Insecure Design

**Problem**
A Byzantine validator that signs two conflicting messages for the same height/round (double-sign / equivocation) violates BFT safety. Without an on-chain slashing mechanism that detects and punishes this behavior, the attack is costless — the validator suffers no economic penalty and can attempt consensus splitting indefinitely.

**Bad Example**
```java
if (votes.containsKey(msg.height())) {
    Msg existing = votes.get(msg.height());
    if (!existing.blockHash().equals(msg.blockHash())) {
        // TODO: slash validator
        return;  // ❌ silent discard — validator pays no penalty
    }
}
```

**Good Example**
```java
if (votes.containsKey(msg.height())) {
    Msg existing = votes.get(msg.height());
    if (!existing.blockHash().equals(msg.blockHash())) {
        // ✅ Record evidence and trigger slashing
        Evidence e = new Evidence(existing, msg);
        slashQueue.submit(e);
        registry.suspend(msg.sender());
        log.error("Equivocation detected for {} at height {}", msg.sender(), msg.height());
        return;
    }
}
```

---

### CON-03: Validator Index Computed from Long Cast to Int

- **Severity**: High
- **CWE**: CWE-190 — Integer Overflow or Wraparound

**Problem**
The current block height or slot number is a `long` that grows monotonically. Using `(int) height % nodes.size()` to select the proposer/leader silently truncates the high 32 bits once `height > Integer.MAX_VALUE` (≈ 2.1 billion blocks). Depending on block time, this can occur within years. The truncation selects the wrong node, causing honest nodes to reject the block.

**Bad Example**
```java
// Proposer selection — height grows without bound
int idx = (int) height % nodes.size();
// When height = 2_200_000_000L:
//   (int) 2_200_000_000L  →  -2_094_967_296  (wraps to negative)
//   -2_094_967_296 % 100  →  negative index
```

**Good Example**
```java
// Modulo on long before narrowing to int
int idx = (int) (height % nodes.size());
// height % 100 always in [0, 99]; safe to cast
```

---

### CON-04: Floating-Point in Validator Reward Distribution

- **Severity**: High
- **CWE**: CWE-1339 — Insufficient Precision or Storage of Numeric Value

**Problem**
Using `double` arithmetic to split block rewards among validators introduces platform-dependent rounding. The same expression can produce different `long` results after truncation on different JVM versions or CPU architectures. If two nodes compute different reward amounts, their state roots diverge and consensus breaks. See also `INT-04` in `common.md`.

**Bad Example**
```java
for (Node n : nodes) {
    long r = (long) (n.weight() * ((double) reward / total));
    // double rounding: x86 and ARM may differ; sum ≠ reward
    credit(n, r);
}
```

**Good Example**
```java
long sum = 0;
for (int i = 0; i < nodes.size(); i++) {
    Node n = nodes.get(i);
    long r = n.weight() * reward / total;  // integer division
    credit(n, r);
    sum += r;
}
// Give undistributed remainder to first node (deterministic)
credit(nodes.get(0), reward - sum);
```

---

### CON-05: Finalized Block Confirmation Threshold Off-by-One or Too Low

- **Severity**: High
- **CWE**: CWE-193 — Off-by-one Error
- **OWASP**: A04:2021 — Insecure Design

**Problem**
BFT finality requires confirmation by at least ⌊2n/3⌋ + 1 nodes (where n = total nodes) to tolerate f = ⌊(n-1)/3⌋ Byzantine nodes. Using `>= (2 * n / 3)` with `>=` but without `+1` sets the threshold one too low: at n=3, `2*3/3 = 2`, so `count >= 2` allows finality with only 2 of 3 nodes — insufficient to tolerate even 1 Byzantine node. The correct form is `>= (2 * n / 3) + 1`, which forces strictly more than two-thirds.

**Bad Example**
```java
// Finality check — >= without +1, threshold one too low
int n = nodes.size();
boolean finalized = count >= (2 * n / 3);
// n=3: 2*3/3=2 → count>=2 → only 2 of 3 needed  ❌ (should need 3)
// n=6: 2*6/3=4 → count>=4 → only 4 of 6 needed  ❌ (should need 5)
```

**Good Example**
```java
// BFT quorum: strictly more than 2/3
int n = nodes.size();
int quorum = (2 * n) / 3 + 1;
boolean finalized = count >= quorum;
// n=3: quorum=3; n=4: quorum=3; n=6: quorum=5 — all correct
```

---

### CON-06: Active Validator List Not Snapshotted Before Use

- **Severity**: Medium
- **CWE**: CWE-362 — TOCTTOU Race Condition

**Problem**
If the active validator list is read once for a check and then read again for action without holding a lock, a concurrent maintenance cycle (epoch transition, slashing) can modify the list between the two reads. The slot calculation may select a validator that is no longer active, or the iteration may see a partially modified list.

**Bad Example**
```java
if (isMyTurn(registry.active(), slot)) {
    // ❌ active() called again — list may have changed
    for (Node n : registry.active()) {
        broadcast(n);
    }
}
```

**Good Example**
```java
List<Node> active = new ArrayList<>(registry.active()); // snapshot
if (isMyTurn(active, slot)) {
    for (Node n : active) {  // use snapshot throughout
        broadcast(n);
    }
}
```
