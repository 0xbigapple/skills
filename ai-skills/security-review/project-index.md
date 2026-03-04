# java-tron Project Index

Maps security-review module names to actual source paths in this repository.

---

## consensus

```
consensus/src/main/java/org/tron/consensus/
  dpos/DposService.java          — DPoS block production scheduling
  dpos/DposSlot.java             — slot assignment, proposer selection
  dpos/DposTask.java             — block production task loop
  dpos/IncentiveManager.java     — validator reward distribution
  dpos/MaintenanceManager.java   — epoch transition, validator set update
  pbft/PbftMessageHandle.java    — PBFT message handler (CON-01, CON-02)
  pbft/PbftManager.java          — PBFT orchestration
```

## p2p

```
framework/src/main/java/org/tron/core/net/
  P2pEventHandlerImpl.java       — top-level message dispatch entry point
  P2pRateLimiter.java            — rate limiter (P2P-01, P2P-04)
  TronNetService.java            — Netty channel initializer (P2P-06)
  peer/PeerConnection.java       — per-peer state, in-flight tracking (P2P-03)
  peer/PeerManager.java          — connection management, IP limits (P2P-05)
  messagehandler/               — per-type message handlers (P2P-02)
  service/sync/SyncService.java  — block sync service
```

## vm

```
actuator/src/main/java/org/tron/core/vm/
  VM.java                        — opcode dispatch loop (VM-01, VM-05)
  JumpTable.java                 — opcode → Operation mapping
  EnergyCost.java                — gas/energy metering (VM-03)
  program/Program.java           — execution context, DELEGATECALL identity (VM-02, VM-04)
  OperationActions.java          — opcode implementations (STATICCALL check)
```

## transaction / actuator

```
actuator/src/main/java/org/tron/core/actuator/
  ActuatorFactory.java           — tx type → actuator routing
  AbstractActuator.java          — validate() + execute() base class (TX-01)
  AccountPermissionUpdateActuator.java — multi-sig weight validation (TX-05)

framework/src/main/java/org/tron/core/db/
  Manager.java                   — tx validation, mempool push, block processing (TX-03, TX-04)
```

## api / http / rpc

```
framework/src/main/java/org/tron/core/services/
  RpcApiService.java             — gRPC server builder (API-02)
  http/                          — 130+ HTTP servlets; look for request body reading (API-03)
  jsonrpc/TronJsonRpcImpl.java   — eth_newFilter, eth_subscribe (API-05)
  jsonrpc/JsonRpcServlet.java    — JSON-RPC entry point (API-01)
  filter/HttpApiAccessFilter.java — HTTP access filter
  filter/HttpInterceptor.java    — request interceptor
```

## crypto

```
crypto/src/main/java/org/tron/common/crypto/
  ECKey.java                     — ECDSA key, signing (CRY-01, CRY-03, CRY-04)
  SignUtils.java                 — sign/verify utilities
  sm2/SM2.java, SM2Signer.java  — SM2 signing (CRY-01)
  zksnark/BN128G1.java           — G1 point (CRY-02)
  zksnark/BN128G2.java           — G2 point (CRY-02)
  zksnark/PairingCheck.java      — pairing verification (CRY-02)
```

## storage / db

```
chainbase/src/main/java/org/tron/core/db2/
  core/SnapshotManager.java      — snapshot stack, flush control (DB-03)
  core/SnapshotImpl.java         — snapshot layer merge (DB-04)
  core/Chainbase.java            — chain tip reference (DB-01)
  common/LevelDB.java            — LevelDB backend, sync options (DB-05)
  common/RocksDB.java            — RocksDB backend, sync options (DB-05)
  common/Flusher.java            — checkpoint flush to disk (DB-02)

chainbase/src/main/java/org/tron/core/store/
  DynamicPropertiesStore.java    — on-chain governance parameters
  CheckPointV2Store.java         — checkpoint store
```

## platform

Cross-cutting — search rather than navigate to a single directory:

```
Grep: Math\.pow|Math\.exp|Math\.sin   → find non-StrictMath FP ops (PLT-01)
Grep: StrictMath                      → verify PLT-01 fixes
Grep: os\.arch|isArm|isX86           → architecture detection logic (PLT-03, PLT-04)
Grep: KNOWN_RESULTS|lookup.*pow       → lookup-table patches (PLT-02)
```

## config

```
framework/src/main/resources/
  config.conf                    — mainnet default configuration
  config-test-net.conf           — testnet configuration

chainbase/src/main/java/org/tron/core/store/
  DynamicPropertiesStore.java    — on-chain parameters (governance-controlled)
```
