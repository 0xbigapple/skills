# EVM / Smart Contract VM Checks

Applies to: bytecode execution engine, opcode dispatch, gas/energy metering, precompiled contracts.
Also load `common.md` (INT-01, INT-02, RACE-01 apply here).

---

### VM-01: Call Depth Check Uses Equality Instead of Greater-or-Equal

- **Severity**: High
- **CWE**: CWE-193 — Off-by-one Error
- **OWASP**: A04:2021 — Insecure Design

**Problem**
The EVM specification defines a hard call-stack limit (EVM: 1024; many L1 VMs: configurable). Using `== MAX_DEPTH` means the check fires only when depth *equals* the limit, but execution at `MAX_DEPTH + 1` is attempted before the check is evaluated in the next frame. Using `>= MAX_DEPTH` is the correct guard. The off-by-one allows one extra call frame, which a crafted contract can exploit to bypass depth-based access controls in inner calls.

**Bad Example**
```java
private static final int MAX_DEPTH = 64;

public void call(Ctx ctx) {
    if (ctx.depth() == MAX_DEPTH) {   // ❌ fires at 64, not at 65
        throw new OutOfResourcesException("call depth limit reached");
    }
    // Execution proceeds; depth can reach 65 before the next check fires
}
```

**Good Example**
```java
public void call(Ctx ctx) {
    if (ctx.depth() >= MAX_DEPTH) {   // ✅ rejects at exactly the limit
        throw new OutOfResourcesException("call depth limit reached");
    }
}
```

---

### VM-02: DELEGATECALL — Caller Identity Set After Repository Access

- **Severity**: Critical
- **CWE**: CWE-665 — Improper Initialization
- **OWASP**: A04:2021 — Insecure Design

**Problem**
`DELEGATECALL` executes the callee's code in the caller's storage context, and `msg.sender` inside the callee must equal the *caller's* caller (i.e., the address that invoked the current frame). If `callerAddress` is written to the new program object *after* it already has a reference to the shared repository, any code inside the new program's initializer (or any permission check that reads `callerAddress` eagerly) sees an uninitialised or wrong identity. This can bypass `require(msg.sender == owner)` guards.

**Bad Example**
```java
Prog p = new Prog(code, repo);   // repo attached at construction
p.setCaller(sender);             // ❌ identity set after repo access
p.execute();
// Callee's initializer already ran with null/wrong caller
```

**Good Example**
```java
// Set ALL context fields before the callee can observe them
Prog p = new Prog(code);
p.setCaller(sender);    // ✅ identity first
p.setOrigin(origin);
p.setValue(value);
p.attachRepo(repo);     // repo last
p.execute();
```

---

### VM-03: Memory Expansion Cost Integer Overflow

- **Severity**: High
- **CWE**: CWE-190 — Integer Overflow or Wraparound

**Problem**
EVM memory expansion cost is quadratic: `cost = words² / 512 + 3 × words`. If `words` is stored as `int` or computed as `int` before the multiplication, `words × words` overflows at `words > 46_340` (since 46341² > Integer.MAX_VALUE). The result wraps to a very small or negative number, and the attacker can allocate large memory regions for near-zero gas/energy — enabling memory exhaustion.

**Bad Example**
```java
int w = toWords(offset + size);           // int type
long cost = (long)(w * w) / 512 + 3 * w;
// If w = 50_000: w * w overflows int before cast to long
```

**Good Example**
```java
long w = toWords(offset + size);          // long throughout
long cost = w * w / 512L + 3L * w;       // all long arithmetic
// Add a sanity cap: if w > MAX_WORDS throw OutOfResourcesException
```

---

### VM-04: Precompiled Contract Receives Execution Context Before Identity Is Set

- **Severity**: Critical
- **CWE**: CWE-665 — Improper Initialization

**Problem**
Precompiled contracts (hash functions, elliptic curve operations, ZK proof verifiers) may perform privileged state writes or access-controlled operations. If the execution context (caller address, origin address) is passed to a precompiled contract *before* it is properly initialised, a permission-sensitive precompile operates under an uninitialised caller identity — potentially allowing unauthorized state mutations.

**Bad Example**
```java
Contract c = registry.get(addr);
c.setRepo(repo);      // ❌ context handed over first
c.setCaller(caller);  // ❌ identity arrives late
byte[] result = c.execute(input);
```

**Good Example**
```java
Contract c = registry.get(addr);
// ✅ Set all identity fields before the contract sees any context
c.setCaller(caller);
c.setOrigin(origin);
c.setValue(value);
c.setRepo(repo);
byte[] result = c.execute(input);
```

---

### VM-05: Static Call Allows State-Modifying Opcode

- **Severity**: High
- **CWE**: CWE-284 — Improper Access Control
- **OWASP**: A01:2021 — Broken Access Control

**Problem**
`STATICCALL` must prohibit all state-modifying opcodes (`SSTORE`, `CREATE`, `SELFDESTRUCT`, `LOG*`, `CALL` with non-zero value). If the VM checks `isStatic` inconsistently — checking it in some opcode handlers but not others — a contract can perform state changes inside a supposed read-only call. This breaks composability guarantees and can corrupt state.

**Bad Example**
```java
// SSTORE handler
case SSTORE:
    if (isStatic) throw new StaticCallModificationException();
    storage.put(key, value);
    break;

// LOG handler — forgotten static check
case LOG0: case LOG1: case LOG2: case LOG3:
    // ❌ No isStatic check — logs emitted inside STATICCALL
    emitLog(topics, data);
    break;
```

**Good Example**
```java
// Centralise the check with a helper used by every state-modifying opcode
private void requireWritable() {
    if (frame.isStatic()) {
        throw new StaticCallModificationException(
            "State modification not allowed in STATICCALL context");
    }
}

case SSTORE:   requireWritable(); storage.put(key, value); break;
case LOG0:     requireWritable(); emitLog(topics, data);   break;
case SELFDESTRUCT: requireWritable(); suicide(target);     break;
```
