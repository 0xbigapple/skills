# P2P / Network Checks

Applies to: peer discovery, message handling, bandwidth control.
Also load `common.md` (OOM-01, NET-01 apply here).

---

### P2P-01: Rate Limiter Default-Allow for Unregistered Message Types

- **Severity**: Critical
- **CWE**: CWE-770 — Allocation of Resources Without Limits or Throttling
- **OWASP**: A05:2021 — Security Misconfiguration

**Problem**
When a rate limiter returns `true` (allow) for message types that have no registered limit entry, every new or unregistered message type is implicitly unlimited. An attacker sends high-frequency messages of an unregistered type — for example, a message type added in a new protocol version before its limiter entry is deployed — and saturates processing threads without triggering any throttle.

**Bad Example**
```java
public boolean tryAcquire(byte type) {
    RateLimiter rl = limiters.get(type);
    if (rl == null) {
        return true;   // ❌ unknown type = unlimited throughput
    }
    return rl.tryAcquire();
}
```

**Good Example**
```java
private final RateLimiter fallback = RateLimiter.create(1.0); // 1 msg/s fallback

public boolean tryAcquire(byte type) {
    RateLimiter rl = limiters.getOrDefault(type, fallback);
    return rl.tryAcquire();
    // Alternative: return false for unregistered types (strict allowlist)
}
```

---

### P2P-02: Message Payload Size Not Validated Before Processing

- **Severity**: High
- **CWE**: CWE-20 — Improper Input Validation
- **OWASP**: A05:2021 — Security Misconfiguration

**Problem**
An inventory or batch message carries a list of hashes or items. Without a maximum count check, a single malicious peer sends a message with hundreds of thousands of items. Each item triggers a lookup and potentially a re-broadcast to all connected peers, creating O(peers × items) amplification. One malicious message becomes a network-wide DoS.

**Bad Example**
```java
public void handle(Peer peer, Msg msg) {
    List<Item> items = msg.items();
    // ❌ No size check — a message with 500,000 items is processed in full
    for (Item item : items) {
        fetch(item);
    }
}
```

**Good Example**
```java
private static final int MAX_ITEMS = 1_000;

public void handle(Peer peer, Msg msg) {
    List<Item> items = msg.items();
    if (items.size() > MAX_ITEMS) {
        peer.disconnect(DisconnectReason.MALFORMED_MESSAGE);
        return;
    }
    for (Item item : items) {
        fetch(item);
    }
}
```

---

### P2P-03: Per-Peer Cache Has No Capacity Bound

- **Severity**: High
- **CWE**: CWE-770 — Allocation of Resources Without Limits or Throttling

**Problem**
Per-peer maps tracking in-flight requests (inventory requests, pending block fetches) use unbounded maps. A misbehaving peer sends requests for non-existent items; responses never arrive; entries accumulate. With `maxConnections = 30` peers each with an unbounded map, heap exhaustion happens when `30 × unlimited_map_entries` exceeds available memory.

**Bad Example**
```java
public class State {
    // Grows without bound — peer sends INV for invented keys, we request them,
    // they never respond, entries never removed
    private final Map<Key, Long> pending = new ConcurrentHashMap<>();
}
```

**Good Example**
```java
public class State {
    private final Cache<Key, Long> pending = CacheBuilder.newBuilder()
        .maximumSize(5_000)                         // per-peer cap
        .expireAfterWrite(30, TimeUnit.SECONDS)     // remove if peer doesn't respond
        .build();
}
```

---

### P2P-04: One Message Type Bypasses Rate Limiting

- **Severity**: High
- **CWE**: CWE-770 — Allocation of Resources Without Limits or Throttling

**Problem**
When rate limiting is applied per-type but only some types are handled, at least one type slips through with no limit. Common omissions: block announcement messages are limited but block body requests are not (or vice versa); transaction gossip is limited but consensus votes are not.

**Bad Example**
```java
public void onMessage(Peer peer, Msg msg) {
    if (msg.type() == TYPE_A) {
        if (!limiter.tryAcquire(TYPE_A)) { peer.disconnect(); return; }
    }
    // ❌ TYPE_B, TYPE_C, TYPE_D pass through unthrottled
    dispatch(msg);
}
```

**Good Example**
```java
public void onMessage(Peer peer, Msg msg) {
    // Apply rate limit to ALL message types
    if (!limiter.tryAcquire(msg.type().code())) {
        log.warn("Rate limit for type {} exceeded by {}", msg.type(), peer.address());
        peer.disconnect(DisconnectReason.TOO_MANY_REQUESTS);
        return;
    }
    dispatch(msg);
}
```

---

### P2P-05: Eclipse Attack — No Peer Diversity Enforcement

- **Severity**: High
- **CWE**: CWE-923 — Improper Restriction of Communication Channel to Intended Endpoints
- **OWASP**: A04:2021 — Insecure Design

**Problem**
Limiting connections to N per IP address does not protect against an attacker who controls multiple IP addresses (cheap VPS, cloud instances). If `maxConnections = 30` and `maxPerIp = 2`, an attacker with 15 IPs fills all connection slots, isolating the victim node. The node then receives only the attacker's view of the blockchain, enabling double-spend or fork-based attacks.

**Bad Example**
```java
public boolean accept(InetAddress addr) {
    return byIp.getOrDefault(addr, 0) < maxPerIp;
    // ❌ An attacker with 15 IPs saturates all 30 slots with 2 connections each
}
```

**Good Example**
```java
public boolean accept(InetAddress addr) {
    // Per-IP limit
    if (byIp.getOrDefault(addr, 0) >= maxPerIp) return false;

    // Per-/24 subnet limit (rough ASN proxy)
    byte[] b = addr.getAddress();
    String subnet = b[0] + "." + b[1] + "." + b[2];
    if (bySubnet.getOrDefault(subnet, 0) >= maxPerSubnet) return false;

    return true;
}
// For stronger protection: integrate ASN or GeoIP lookups
```

---

### P2P-06: P2P Channel Transmits All Data Without Transport Encryption

- **Severity**: High
- **CWE**: CWE-319 — Cleartext Transmission of Sensitive Information

**Problem**
When the Netty pipeline for peer-to-peer connections contains no `SslHandler` (or equivalent transport-layer encryption), all TCP traffic between nodes is transmitted in plaintext. A network-path attacker can: (1) eavesdrop on block data, transaction data, and consensus messages; (2) inject forged `DISCONNECT` frames to sever legitimate connections; (3) perform a man-in-the-middle attack to modify transactions in transit before they are signature-verified. Without transport encryption, the entire communication channel depends solely on application-layer signature checks — which only protect against forgery, not interception.

**Bad Example**
```java
// Netty channel initializer — no SslHandler in the pipeline
@Override
public void initChannel(SocketChannel ch) throws Exception {
    ChannelPipeline pipeline = ch.pipeline();
    pipeline.addLast("timeout",      new ReadTimeoutHandler(readTimeout));
    pipeline.addLast("frameDecoder", new ProtobufVarint32FrameDecoder());
    pipeline.addLast("frameEncoder", new ProtobufVarint32LengthFieldPrepender());
    pipeline.addLast("handler",      new MessageHandler());
    // ❌ No SslHandler — all peer traffic is plaintext on the wire
}
```

**Good Example**
```java
@Override
public void initChannel(SocketChannel ch) throws Exception {
    ChannelPipeline pipeline = ch.pipeline();
    // ✅ TLS handler must be first in the pipeline
    SslContext sslCtx = SslContextBuilder.forServer(certFile, keyFile)
        .clientAuth(ClientAuth.REQUIRE)
        .build();
    pipeline.addLast(sslCtx.newHandler(ch.alloc()));
    pipeline.addLast("timeout",      new ReadTimeoutHandler(readTimeout));
    pipeline.addLast("frameDecoder", new ProtobufVarint32FrameDecoder());
    pipeline.addLast("frameEncoder", new ProtobufVarint32LengthFieldPrepender());
    pipeline.addLast("handler",      new MessageHandler());
}
// Alternative: implement a Noise Protocol or devp2p RLPx handshake
// for mutual authentication + encryption using each node's existing ECDSA key pair.
```

---

### P2P-07: Peer Address Validator Accepts Private and Reserved IP Ranges

- **Severity**: Medium
- **CWE**: CWE-20 — Improper Input Validation

**Problem**
A peer validation function that checks only IP format correctness (parseable, not empty) without rejecting RFC 1918 private ranges and other reserved blocks allows malicious nodes to inject internal addresses (`127.x`, `10.x`, `172.16–31.x`, `192.168.x`, `169.254.x`) into the routing table via discovery messages. The node then attempts to connect to these addresses, wasting connection slots on unreachable entries and — in cloud or data-center environments — potentially triggering connections to internal metadata services or other services that trust the node's source IP. Flooding the routing table with unconnectable private addresses also displaces legitimate peers, aiding an eclipse attack.

**Bad Example**
```java
public static boolean isValidPeer(String ip, int port) {
    try {
        InetAddress addr = InetAddress.getByName(ip);
        return addr != null && port > 0 && port <= 65535;
        // ❌ 127.0.0.1, 10.x.x.x, 192.168.x.x all pass — internal addresses accepted
    } catch (UnknownHostException e) {
        return false;
    }
}
```

**Good Example**
```java
public static boolean isValidPeer(String ip, int port) {
    if (port <= 0 || port > 65535) return false;
    try {
        InetAddress addr = InetAddress.getByName(ip);
        // ✅ Reject all non-routable and reserved address ranges
        if (addr.isLoopbackAddress()      // 127.x.x.x / ::1
            || addr.isLinkLocalAddress()  // 169.254.x.x / fe80::/10
            || addr.isSiteLocalAddress()  // 10.x, 172.16-31.x, 192.168.x
            || addr.isMulticastAddress()  // 224.x.x.x
            || addr.isAnyLocalAddress()   // 0.0.0.0
        ) {
            return false;
        }
        return true;
    } catch (UnknownHostException e) {
        return false;
    }
}
```

---

### P2P-08: Compressed P2P Message Payload Without Decompression Ratio Limit

- **Severity**: High
- **CWE**: CWE-409 — Improper Handling of Highly Compressed Data (Zip Bomb)

**Problem**
When P2P messages support a compression layer (Snappy, LZ4, gzip), decompression is performed before the uncompressed size limit is enforced. An attacker sends a tiny compressed payload (e.g., 100 bytes of repeated zeros compressed to near zero) that decompresses to hundreds of megabytes. The node allocates the full output buffer before detecting the size violation. Without a compression ratio check, the limit on the declared uncompressed size (from the header) can be bypassed: the header may lie, or the expansion may occur in streaming chunks that each appear within the limit. With N concurrent connections each sending such messages, heap is exhausted.

**Bad Example**
```java
public static byte[] decompress(byte[] compressed) throws IOException {
    int declaredSize = Snappy.uncompressedLength(compressed); // reads header only
    if (declaredSize > MAX_MESSAGE_SIZE) {
        throw new ProtocolException("Message too large: " + declaredSize);
    }
    // ❌ Full allocation happens here; compression ratio unchecked;
    //    adversarial header can understate actual expansion
    return Snappy.uncompress(compressed);
}
```

**Good Example**
```java
private static final int MAX_UNCOMPRESSED_BYTES  = 10 * 1024 * 1024; // 10 MB
private static final int MAX_COMPRESSION_RATIO   = 100;               // 100:1

public static byte[] decompress(byte[] compressed) throws IOException {
    if (compressed.length == 0) return compressed;

    int declaredSize = Snappy.uncompressedLength(compressed);

    // ✅ Reject implausible compression ratios before allocating
    if (declaredSize / compressed.length > MAX_COMPRESSION_RATIO) {
        throw new ProtocolException(
            "Compression ratio " + (declaredSize / compressed.length)
            + ":1 exceeds limit of " + MAX_COMPRESSION_RATIO + ":1");
    }
    if (declaredSize > MAX_UNCOMPRESSED_BYTES) {
        throw new ProtocolException("Declared uncompressed size exceeds limit");
    }

    byte[] result = Snappy.uncompress(compressed);

    // ✅ Also verify the actual decompressed size (header may lie)
    if (result.length > MAX_UNCOMPRESSED_BYTES) {
        throw new ProtocolException("Actual decompressed size exceeds limit");
    }
    return result;
}
```
