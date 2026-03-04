# Storage / State Database Checks

Applies to: snapshot management, checkpoint recovery, state trie, database write-ahead log.
Also load `common.md` (RACE-01, OOM-01 apply here).

---

### DB-01: Shared State Field Not Visible Across Threads

- **Severity**: High
- **CWE**: CWE-362 — Concurrent Execution Using Shared Resource with Improper Synchronization

**Problem**
The chain tip (latest block reference) is written by the block-processing thread and read by API threads. Without `volatile` or an `AtomicReference`, the JVM memory model does not guarantee that the write is visible to the reading thread. A stale read silently returns data from an earlier state without any error signal. See also `RACE-01` in `common.md`.

**Bad Example**
```java
public class StateDatabase {
    private Snapshot latestSnapshot;   // ❌ no volatile

    public void commit(Snapshot s)     { this.latestSnapshot = s; }     // block thread
    public Snapshot getLatest()        { return latestSnapshot; }        // API thread — may be stale
}
```

**Good Example**
```java
public class StateDatabase {
    private volatile Snapshot latestSnapshot;
    // OR: private final AtomicReference<Snapshot> latestSnapshot = new AtomicReference<>();
}
```

---

### DB-02: Checkpoint Restore Is Not Atomic

- **Severity**: High
- **CWE**: CWE-362 — Race Condition During Restore
- **OWASP**: A04:2021 — Insecure Design

**Problem**
On crash recovery, the node restores from the last checkpoint by replaying records into each store sequentially. If the process is killed mid-restore (power loss, OOM), some stores are at the checkpoint state while others remain at a later state. The node restarts with an internally inconsistent database — state from different points in time combined into one logical state.

**Bad Example**
```java
public void restoreFromCheckpoint(Checkpoint cp) {
    for (Store store : stores) {
        store.applyCheckpoint(cp);  // ❌ no atomicity — crash here leaves partial state
    }
    // No marker written to indicate restore completed
}
```

**Good Example**
```java
public void restoreFromCheckpoint(Checkpoint cp) {
    Path markerFile = dataDir.resolve("restore.inprogress");
    Files.createFile(markerFile);  // presence signals incomplete restore on next boot

    try {
        for (Store store : stores) {
            store.applyCheckpoint(cp);
        }
        Files.delete(markerFile);  // ✅ marker removed only after all stores are updated
    } catch (Exception e) {
        // On next start: detect marker → delete partial data → re-download checkpoint
        throw new DatabaseRecoveryException("Checkpoint restore failed", e);
    }
}
```

---

### DB-03: Snapshot Stack Depth Unbounded Under Long Forks

- **Severity**: High
- **CWE**: CWE-770 — Allocation of Resources Without Limits or Throttling

**Problem**
Each unconfirmed block appends a snapshot layer to the in-memory stack. The stack is bounded by a constant, but if the eviction path is guarded by a flag that can be set to suppress flushing (e.g., `hitDown`, `pauseFlush`), the stack grows without bound when that flag is active. An attacker sustains a long alternative fork, holding the flag active and continuously appending layers until OOM.

**Bad Example**
```java
private static final int MAX_STACK_DEPTH = 256;

public void pushSnapshot(Snapshot s) {
    if (stack.size() > MAX_STACK_DEPTH && !suppressFlush) {
        flushOldest();  // ❌ skipped entirely when suppressFlush=true
    }
    stack.push(s);  // ❌ grows beyond MAX_STACK_DEPTH when flush is suppressed
}
```

**Good Example**
```java
public void pushSnapshot(Snapshot s) {
    if (stack.size() >= MAX_STACK_DEPTH) {
        // Hard limit: reject rather than grow beyond bound
        throw new SnapshotOverflowException(
            "Snapshot stack limit reached (" + MAX_STACK_DEPTH + "). Possible long-fork attack.");
    }
    stack.push(s);
}
// Separately track suppressFlush for operational use, but never let it bypass the hard cap
```

---

### DB-04: State Merge Not Synchronized — Concurrent Readers See Torn State

- **Severity**: High
- **CWE**: CWE-362 — Concurrent Execution Using Shared Resource with Improper Synchronization

**Problem**
Merging (collapsing) snapshot layers into the base store modifies the data structure while API threads may be iterating over it to serve queries. Without holding a write lock for the full merge operation, a reader can observe partially merged data — some keys at the new value and some still at the old, producing an inconsistent view.

**Bad Example**
```java
public void mergeSnapshots() {
    // ❌ No lock — API threads may read snapshot chain concurrently
    for (Map.Entry<Key, Value> entry : pendingSnapshot.entrySet()) {
        baseStore.put(entry.getKey(), entry.getValue());
    }
    snapshots.removeFirst();
}
```

**Good Example**
```java
private final ReadWriteLock lock = new ReentrantReadWriteLock();

public void mergeSnapshots() {
    lock.writeLock().lock();
    try {
        for (Map.Entry<Key, Value> entry : pendingSnapshot.entrySet()) {
            baseStore.put(entry.getKey(), entry.getValue());
        }
        snapshots.removeFirst();
    } finally {
        lock.writeLock().unlock();
    }
}

public Value read(Key key) {
    lock.readLock().lock();
    try {
        return lookup(key);
    } finally {
        lock.readLock().unlock();
    }
}
```

---

### DB-05: Database Opened With fsync Disabled in Production

- **Severity**: High
- **CWE**: CWE-400 — Uncontrolled Resource Consumption (Data Loss Variant)
- **OWASP**: A05:2021 — Security Misconfiguration

**Problem**
Database backends (RocksDB, LevelDB) support an async write mode that skips `fsync()` after each write batch for higher throughput. In a crash (power loss, OOM kill, kernel panic), writes in the OS page cache but not yet persisted to disk are silently lost. The node restarts with a database that does not correspond to any valid block height, requiring a full resync which can take hours or days.

**Bad Example**
```java
// RocksDB options — production config
Options options = new Options();
options.setSync(false);          // ❌ async writes, data loss on crash
// or: options.setDisableWAL(true);  // ❌ disables write-ahead log entirely
```

**Good Example**
```java
// Production: sync enabled for durability
Options options = new Options();
options.setSync(true);           // ✅ fsync after each write batch
// Trade-off: lower write throughput; acceptable for correctness

// If throughput is critical, use WAL + periodic sync instead of per-write sync:
// options.setSync(false);
// options.setWalSizeLimitMB(64);   // WAL caps risk window
// Schedule periodic manual sync
```
