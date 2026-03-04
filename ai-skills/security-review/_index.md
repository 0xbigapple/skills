# Security Review — Check Index

Each check lives in its module file. Read the relevant file(s) for the code under review; load `common.md` alongside any module file (common checks cross-apply everywhere).

---

## Module Files

| File | Prefix | Covers |
|------|--------|--------|
| `common.md` | INT, RACE, OOM, DESER, ERR, NET | Arithmetic, concurrency, memory, deserialization, error handling, logging |
| `consensus.md` | CON | BFT/DPoS engine, validator scheduling, finality |
| `p2p.md` | P2P | Peer discovery, message handling, bandwidth control |
| `vm.md` | VM | Bytecode execution, gas/energy metering, precompiles |
| `transaction.md` | TX | Transaction validation, execution, fee handling, mempool |
| `api.md` | API | HTTP servlet, gRPC, JSON-RPC |
| `crypto.md` | CRY | Key management, signing, hashing, ZK proof verification |
| `storage.md` | DB | Snapshot management, checkpoint recovery, state DB |
| `platform.md` | PLT | Cross-platform floating-point consistency, architecture detection |
| `config.md` | CFG | Node configuration files and deployment settings |

---

## Next Available IDs

| File | Next ID |
|------|---------|
| common | INT-05, RACE-03, OOM-02, DESER-02, ERR-03, NET-03 |
| consensus | CON-07 |
| p2p | P2P-09 |
| vm | VM-06 |
| transaction | TX-06 |
| api | API-07 |
| crypto | CRY-05 |
| storage | DB-06 |
| platform | PLT-05 |
| config | CFG-06 |

---

## Common Checks Cross-Reference

The following checks from `common.md` also apply inside specific modules:

| Common Check | Applies In | Why |
|--------------|-----------|-----|
| INT-01, INT-02, INT-04 | consensus, vm, transaction | Slot arithmetic, gas, balances |
| INT-03 | transaction | Checked result discarded before DB write |
| RACE-01, RACE-02 | consensus, storage | Chain tip, block producer scheduling |
| OOM-01 | p2p, api | Network-fed collections |
| DESER-01 | api, p2p | Untrusted input deserialization |
| ERR-01, NET-01 | api | HTTP handler error handling |
| ERR-02 | consensus, p2p, transaction | Signature/validation exception swallowed in message handlers |
| NET-02 | p2p, api | External peer data or request fields written to logs |
