# Cross-Platform Consistency Checks

Applies to: any Java blockchain node that ships different code or uses different libraries across CPU architectures (x86 vs ARM64) or JVM versions (JDK 8 vs JDK 17+).

These issues are unique to nodes with conditional compilation or platform-adaptive code. Skip this file if the project targets a single JVM/architecture combination.

---

### PLT-01: Floating-Point Operation Produces Different Results on Different Platforms

- **Severity**: Critical
- **CWE**: CWE-1339 — Insufficient Precision or Storage of Numeric Value
- **OWASP**: A04:2021 — Insecure Design

**Problem**
`Math.pow()`, `Math.sin()`, `Math.exp()`, and other `java.lang.Math` methods delegate to native hardware FPU instructions, whose precision and rounding mode vary between x86 (80-bit extended precision on x87) and ARM64 (strict IEEE 754 64-bit). The same call can return different bit-level `double` results. When converted to `long` via `(long)` truncation, the difference becomes a different token amount — and two nodes on different architectures compute different state roots, causing a consensus fork.

`StrictMath` (or `java.lang.StrictMath`) is mandated by the JVM specification to produce identical results on all platforms. It should be used for any calculation that affects consensus state.

**Bad Example**
```java
// Platform-dependent — x86 and ARM may differ
public double computeYield(double principal, double rate, double periods) {
    return principal * Math.pow(1 + rate, periods);  // ❌ Math.pow varies by platform
}
long yield = (long) computeYield(balance, 0.001, 2000.0);
// x86 nodes and ARM64 nodes compute different yield → different balances → fork
```

**Good Example**
```java
// Platform-independent — identical on all JVM implementations
public double computeYield(double principal, double rate, double periods) {
    return principal * StrictMath.pow(1 + rate, periods);  // ✅ StrictMath
}
// Better: eliminate floating-point entirely (see INT-04 in common.md)
```

---

### PLT-02: Lookup Table Used to Patch Known Floating-Point Divergences

- **Severity**: Critical
- **CWE**: CWE-1339 — Insufficient Precision or Storage of Numeric Value

**Problem**
Some projects address cross-platform floating-point divergence by shipping a hardcoded lookup table of (input → expected output) pairs for historically observed divergent values, falling back to `StrictMath` for unrecognized inputs. This patch strategy cannot cover future inputs: any new combination of parameters that diverges between platforms but is not in the table produces a consensus-breaking discrepancy. The lookup table also creates a maintenance burden and can be bypassed by an attacker who engineers inputs not in the table.

**Bad Example**
```java
// ARM implementation — lookup table for historically divergent pow() inputs
private static final Map<PowKey, Double> KNOWN_RESULTS = new HashMap<>();
static {
    KNOWN_RESULTS.put(new PowKey(1.001, 2000.0), 7.389056099);  // block 4137160
    // ... 77 more entries
}

public static double pow(double a, double b) {
    Double patched = KNOWN_RESULTS.get(new PowKey(a, b));
    return (patched != null) ? patched : StrictMath.pow(a, b);
    // ❌ New inputs not in table → potential divergence from x86 nodes
}
```

**Good Example**
```java
// Solution A: Eliminate floating-point entirely for consensus-critical math
//   → use integer arithmetic with fixed-point scaling

// Solution B: Use StrictMath everywhere on both platforms, removing the lookup table
//   → requires verifying that StrictMath.pow() matches the historical chain data

// Solution C: Use a deterministic software floating-point library
//   → e.g., SoftFloat or a pure-Java IEEE 754 implementation
//   → same result on all platforms regardless of hardware FPU
```

---

### PLT-03: Architecture Detection Based on Negation Instead of Explicit Check

- **Severity**: Medium
- **CWE**: CWE-20 — Improper Input Validation

**Problem**
Defining `isX86()` as `!isArm64()` silently classifies any non-ARM64 architecture (RISC-V, MIPS, s390x, POWER) as x86. These architectures load the x86 code path — which may use platform-dependent math or outdated library versions — and produce consensus results that differ from both the intended x86 and ARM64 implementations. As RISC-V servers become more common in cloud infrastructure, this becomes an increasingly realistic scenario.

**Bad Example**
```java
public static boolean isX86() {
    return !isArm64();   // ❌ RISC-V, MIPS, POWER all mapped to "x86"
}
```

**Good Example**
```java
public static boolean isX86_64() {
    String arch = System.getProperty("os.arch", "").toLowerCase();
    return arch.equals("x86_64") || arch.equals("amd64");
}

public static boolean isArm64() {
    String arch = System.getProperty("os.arch", "").toLowerCase();
    return arch.equals("aarch64") || arch.equals("arm64");
}

public static void requireSupportedArchitecture() {
    if (!isX86_64() && !isArm64()) {
        throw new UnsupportedOperationException(
            "Unsupported CPU architecture: " + System.getProperty("os.arch")
            + ". Only x86_64 and aarch64 are validated for consensus correctness.");
    }
}
```

---

### PLT-04: System Property Used for Architecture Detection Can Be Spoofed

- **Severity**: Medium
- **CWE**: CWE-20 — Improper Input Validation

**Problem**
`System.getProperty("os.arch")` can be overridden at JVM startup via `-Dos.arch=aarch64`. An operator who starts a node with a spoofed arch string loads the wrong math library — for example, x86 `Math.pow()` on an ARM machine, or ARM's lookup-table-patched version on an x86 machine. The mismatch is silent and produces incorrect consensus results without any error.

**Bad Example**
```java
// Architecture detection based on spoofable JVM property
public static boolean isArm64() {
    return "aarch64".equals(System.getProperty("os.arch"));
    // An attacker / misconfigured operator runs: java -Dos.arch=aarch64 -jar node.jar
    // → ARM code path loads on x86 hardware → wrong math results
}
```

**Good Example**
```java
// Log the detected architecture prominently at startup for operator visibility
String detectedArch = System.getProperty("os.arch", "unknown");
logger.info("Architecture: os.arch={}, detected={}",
    detectedArch, isArm64() ? "arm64" : isX86_64() ? "x86_64" : "unsupported");

// Optionally, cross-validate with a native call that cannot be overridden:
// String nativeArch = getNativeArchViaJNA(); // uname(2) MACHINE field
// if (!nativeArch.equals(detectedArch)) { logger.warn("os.arch mismatch"); }
```
