# Configuration Security Checks

Applies to: node configuration files, deployment scripts, environment setup.
Configuration issues cannot be found by reading Java source alone — always read the actual config file and deployment scripts.

---

### CFG-01: Validator Private Key in Plaintext Configuration

- **Severity**: Critical
- **CWE**: CWE-312 — Cleartext Storage of Sensitive Information
- **OWASP**: A02:2021 — Cryptographic Failures

**Problem**
Storing a validator (block producer) private key as a hex string directly in a configuration file exposes it to anyone with read access to the file system, configuration management systems, container image layers, or log files. The key also appears in process arguments when passed via CLI (`-p <key>`), visible to any user running `ps -ef` on the host. A leaked validator key allows an attacker to produce fraudulent blocks, steal block rewards, and sign transactions from the validator account.

**Bad Example**
```hocon
# config.conf
validator.privateKey = "da146374a75310b9666e834ee4ad0866d6f4035967bfc76217c5a495fff9f0d0"
# Also problematic:
# java -jar node.jar --private-key da1463...
```

**Good Example**
```hocon
# Use an encrypted keystore file — private key is AES-encrypted with a password
validator.keystoreFile = "/secure/path/validator-keystore.json"
# Keystore password supplied via environment variable (never in config):
# export VALIDATOR_KEYSTORE_PASSWORD=<password>

# File permissions:
# chmod 600 /secure/path/validator-keystore.json
# chown nodeuser:nodeuser /secure/path/validator-keystore.json
```

---

### CFG-02: API Rate Limiting Disabled or Set to Permissive Defaults

- **Severity**: High
- **CWE**: CWE-770 — Allocation of Resources Without Limits or Throttling
- **OWASP**: A05:2021 — Security Misconfiguration

**Problem**
Blockchain nodes commonly ship with all rate limiting rules commented out or set to very high defaults (e.g., 50,000 QPS globally) for development convenience. In production, these settings allow a single attacker to consume all processing capacity with an HTTP or gRPC flood, delaying the node's ability to validate and relay transactions — and in the worst case, missing a block production slot.

**Bad Example**
```hocon
rateLimit {
  # http rules commented out — no per-endpoint limit
  global.qps = 50000       # effectively unlimited
  global.ip.qps = 10000    # 10k requests/sec from one IP allowed
}
```

**Good Example**
```hocon
rateLimit {
  http = [
    { endpoint = "broadcastTransaction", qps = 20,  strategy = "per-ip" },
    { endpoint = "triggerContract",      qps = 50,  strategy = "per-ip" },
    { endpoint = "getBlock",             qps = 200, strategy = "global" }
  ]
  grpc = [
    { method = "BroadcastTransaction",   qps = 20,  strategy = "per-ip" }
  ]
  global.qps = 2000        # hard cap on all traffic
  global.ip.qps = 200      # per-IP hard cap
}
```

---

### CFG-03: Database Written Without fsync (Async Mode)

- **Severity**: High
- **CWE**: CWE-400 — Uncontrolled Resource Consumption (Data Durability)
- **OWASP**: A05:2021 — Security Misconfiguration

**Problem**
Setting `db.sync = false` (or equivalent) tells the storage engine (RocksDB, LevelDB) to skip `fsync()` after each write, relying on the OS page cache for persistence. On a crash (power loss, OOM kill, kernel panic), any writes in the page cache but not yet on disk are silently lost. The node restarts with a partially written database that does not correspond to any valid chain state, requiring a full resync.

**Bad Example**
```hocon
storage {
  db.sync = false       # ❌ async write — data loss on crash
  # checkpoint.sync = true   # also commented out
}
```

**Good Example**
```hocon
storage {
  db.sync = true         # ✅ fsync after each write batch (production)
  checkpoint.sync = true # ✅ checkpoints flushed to disk
}
# Trade-off: ~10–20% write throughput reduction vs data durability guarantee
```

---

### CFG-04: All API Ports Bound to All Interfaces (0.0.0.0) Without TLS

- **Severity**: High
- **CWE**: CWE-306 — Missing Authentication for Critical Function
- **OWASP**: A07:2021 — Identification and Authentication Failures

**Problem**
Blockchain node APIs default to binding on all network interfaces (`0.0.0.0`) with plaintext transport and no authentication. Anyone who can reach the host's IP and port can invoke all APIs — including transaction broadcast, mempool queries, and in some implementations wallet operations. Standard port numbers (8545 for Ethereum JSON-RPC, 8080/8090 for HTTP, 50051 for gRPC) are actively scanned by internet-wide scanners.

**Bad Example**
```hocon
node {
  http.port = 8090       # binds 0.0.0.0:8090, no TLS, no auth
  grpc.port = 50051      # binds 0.0.0.0:50051, plaintext gRPC
  jsonrpc.port = 8545    # Ethereum-compatible port — heavily scanned
}
```

**Good Example**
```hocon
# Option A: Bind to loopback and use an authenticated reverse proxy for external access
node {
  http.bindAddress = "127.0.0.1"   # loopback only
  http.port = 8090
}
# nginx terminates TLS at 0.0.0.0:443 and proxies to 127.0.0.1:8090

# Option B: Disable unused API surfaces
node {
  jsonrpc.enabled = false   # disable if not needed
  http.walletApiEnabled = false
}

# Option C: Firewall rules restrict port access to trusted CIDR
# iptables -A INPUT -p tcp --dport 8090 -s 10.0.0.0/8 -j ACCEPT
# iptables -A INPUT -p tcp --dport 8090 -j DROP
```

---

### CFG-05: Event Bus / Message Queue Port Exposed Without Authentication

- **Severity**: Medium
- **CWE**: CWE-306 — Missing Authentication for Critical Function

**Problem**
Some blockchain nodes publish real-time events (new blocks, transactions, contract events) over an internal message bus (ZeroMQ PUB socket, Kafka topic, NATS subject). If this bus port is bound to all interfaces without authentication, any network client can subscribe and receive real-time chain data — leaking transaction timing, mempool contents, and block production patterns to adversaries who can use this for MEV or frontrunning.

**Bad Example**
```hocon
eventBus {
  type = "zmq"
  port = 5555         # ❌ binds 0.0.0.0:5555, no authentication
}
```

**Good Example**
```hocon
eventBus {
  type = "zmq"
  bindAddress = "127.0.0.1"  # ✅ loopback only — remote consumers must tunnel
  port = 5555
  # For remote consumers: use ZMQ CURVE authentication
  # curveCertFile = "/secure/path/server.cert"
}
```
