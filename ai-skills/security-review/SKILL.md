---
name: security-review
description: Targeted security audit for Java blockchain nodes. Use when asked to audit a module, file, or vulnerability type. Examples: /security-review consensus, /security-review p2p, /security-review overflow, /security-review config
---

# Java Blockchain Node — Security Review

Perform a targeted security audit: read actual source code, apply checks from the knowledge base, output structured findings.

---

## STEP 1 — Determine Scope

Parse the argument to select which check files to load from `.claude/skills/security-review/checks/`:

| Argument | Check Files |
|----------|-------------|
| *(none)* | `common.md` + quick scan (see §Risk Map below) |
| `consensus` | `consensus.md` + `common.md` |
| `p2p` / `net` | `p2p.md` + `common.md` |
| `vm` / `evm` / `tvm` | `vm.md` + `common.md` |
| `tx` / `actuator` / `transaction` | `transaction.md` + `common.md` |
| `api` / `http` / `rpc` | `api.md` + `common.md` |
| `crypto` | `crypto.md` + `common.md` |
| `db` / `storage` / `state` | `storage.md` + `common.md` |
| `platform` / `cross` / `arch` | `platform.md` + `common.md` |
| `config` | `config.md` |
| `all` | All check files |
| Vulnerability keyword (`overflow`, `race`, `dos`, `auth`, `deserialization`, `crypto`) | `common.md` + all module files |
| File path or class name | `common.md` + nearest module file |

### §Risk Map — No-Argument Quick Scan

When no argument is given, apply these checks to the first matching file you find:

| Priority | What to Find | Check IDs |
|----------|-------------|-----------|
| 1 | Consensus message handler (PBFT/Tendermint/HotStuff `on*` methods) | CON-01, CON-02 |
| 2 | P2P rate limiter (`tryAcquire` / `acquire` entry point) | P2P-01 |
| 3 | VM call dispatcher (`CALL`/`DELEGATECALL` handling) | VM-01, VM-02 |
| 4 | Slot/epoch index arithmetic (consensus scheduling) | INT-01 |
| 5 | Database snapshot/checkpoint restore | DB-02, DB-03 |

---

## STEP 2 — Locate Source Files

**Always read actual code. Do not rely on memory.**

### 2a. Find files

For project-specific paths, consult `project-index.md` in this skill directory if it exists.

Otherwise, derive file locations from the check items themselves: each **Bad Example** encodes the pattern to search for. Extract its key identifiers and run searches like:

```
Glob  **/*RateLimiter*.java
Grep  tryAcquire
Grep  JSON\.parseObject
Grep  \(int\).*slot\|epoch\|height
```

Use the module scope from STEP 1 to restrict search directories and reduce noise.

### 2b. Search principles

- **Treat Bad Example patterns as starting points, not complete checklists.** The same vulnerability may appear under different variable or method names. If you find a suspicious pattern not covered by the Bad Example, investigate it anyway.
- **Do not anchor to names.** A rate limiter may be called `throttle`, `quota`, or `guard` — not just `rateLimiter`. A validator index may be called `proposerIdx`, `leaderPos`, or `slotOwner`.
- **Follow the data.** For overflow checks, trace the value from its source (block height, balance fetch) through arithmetic to its use (array index, database write). The Bad Example shows one shape of the problem; look for the shape in the actual code, not the exact names.

---

## STEP 3 — Apply Checks

For each source file read, go through every check item in the loaded check files.

Each check item contains:
- **Problem** — what the vulnerability is and why it matters
- **Bad Example** — the vulnerable pattern (generic Java code)
- **Good Example** — the correct pattern

Apply the search principles from STEP 2b to locate the pattern in the actual code.
Mark each check: **Found** / **Not Found** / **N/A** (internal tracking only — Not Found and N/A items do not appear in the report).

---

## STEP 4 — Output Report

Output findings using exactly this structure. Omit sections with zero findings. Order by severity.

```
# Security Review: [Scope]

**Date**: YYYY-MM-DD
**Files Read**: [every file actually read]
**Checks Applied**: [check IDs applied, e.g. INT-01, CON-02]

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | N |
| High     | N |
| Medium   | N |
| Low      | N |

---

## Findings

### [CHECK-ID] [Title]

- **Severity**: Critical / High / Medium / Low
- **CWE**: CWE-XXX — [Name]
- **OWASP**: [Category] *(if applicable)*
- **File**: `path/to/ActualFile.java:LINE`

**Observed Code**
```java
// exact lines from the file, including surrounding context
```

**Why It Is a Problem**
[One paragraph: which invariant is violated, concrete consequence]

**Reproduction Steps**
1. [Specific named method/class]
2. [Trigger condition]
3. [Expected vs actual outcome]

**Recommended Fix**
```java
// concrete replacement code
```

**Verification**
[Specific grep or test that confirms the fix is in place]

---
```

---

## Severity Definitions

| Level | Meaning |
|-------|---------|
| **Critical** | Directly exploitable: fund loss, consensus split, RCE, full-node crash with no prerequisites |
| **High** | Requires specific conditions; significant impact: DoS, data corruption, auth bypass |
| **Medium** | Partial or chained impact; needs multiple conditions to exploit |
| **Low** | Defense-in-depth gap; minimal standalone impact |

---

## Extending This Skill

**Add a check to an existing file:**
1. Find the next available ID in `_index.md` (Next Available IDs table).
2. Copy the item template from `_template.md`.
3. Append the new item to the target module file.
4. Update the Next Available IDs table in `_index.md`.

**Add a new module check file:**
1. Create `checks/<module>.md` — use `_template.md` for item format guidance.
2. Add a row to the scope table in STEP 1.
3. Add a row to the Module Files table in `_index.md` and add a Next Available IDs entry.

**Add project-specific file paths:**
- Create `project-index.md` in this skill directory mapping module names to actual source paths.

**Reference materials (all self-contained in this skill directory):**
- Item format spec + CWE/OWASP quick picks: `_template.md`
- All check IDs and next available numbers: `_index.md`
