# ADR 0002: Asynchronous Storage Abstraction & Distributed Redis Backend with Automated TTL

## Status
**ACCEPTED** (2026-11-05)

## Context
Initial implementations of the compliance engine stored ephemeral token mappings inside an in-memory dictionary guarded by a single global `threading.Lock()`. In an enterprise production environment, this architecture introduces critical flaws:
1. **Thread Contention & Lock Convoying**: Under high concurrent throughput across worker threads, a single global lock serializes read and write access, crippling latency.
2. **Unbounded Memory Accumulation (OOM)**: Storing session mappings indefinitely in memory without an automated eviction or expiration mechanism eventually exhausts container RAM.
3. **Multi-Replica State Desynchronization**: In a horizontally autoscaled Kubernetes environment, multiple gateway pods cannot share in-memory state. If a response arrives at Pod B while Pod A masked the request, unmasking fails.
4. **GDPR Right-to-Erasure**: Regulatory standards mandate that temporary pseudonymization tables must not persist indefinitely.

## Decision
We abstract the persistence layer behind an asynchronous interface `BaseTokenStorage` in [app/storage.py](file:///c:/WWORKING_folder/ProjectFolders/zero-trust-llm-compliance-gateway/app/storage.py) and provide two production-grade implementations:

1. **`InMemoryTokenStorage`**:
   - Uses reentrant fine-grained locking (`threading.RLock`) to prevent self-deadlocks.
   - Provides dual synchronous and asynchronous methods (`get_or_create_token_sync` / `get_or_create_token`) to preserve 100% backward compatibility for local test harnesses and development environments.
2. **`RedisTokenStorage`**:
   - Uses non-blocking `redis.asyncio` with connection pooling.
   - Partitions token vaults into session namespaces: `compliance:vault:{session_id}:tokens`, `values`, and `counters`.
   - Utilizes atomic Redis `HINCRBY` commands for collision-free token counter generation across concurrent workers.
   - Enforces an automated Time-To-Live (TTL, default 3,600s) on all keys, refreshed upon every read and write, ensuring automatic GDPR-compliant session cleanup.
3. **Fail-Closed Storage Health Probes**:
   - `health_check_async()` actively probes `storage.ping()`. If Redis becomes unreachable, the gateway fails closed by raising `ComplianceEngineCrashError` (HTTP 503), preventing unmasked prompt leakage.

## Consequences

### Positive
- **Horizontal Scalability**: Gateway pods are fully stateless; any pod can mask a prompt and any other pod can unmask the LLM response.
- **Bounded Memory & Regulatory Compliance**: Redis manages key expiration automatically via 3,600s TTLs, preventing memory leaks and satisfying GDPR data minimization mandates.
- **High Concurrency**: Redis handles token reads and writes asynchronously in microsecond durations without Python GIL contention.
- **Zero-Dependency Testability**: `InMemoryTokenStorage` and simulated Redis client mocks in `tests/conftest.py` allow full test execution without requiring a live external Redis daemon.

### Negative / Tradeoffs
- Requires provisioning and operating a high-availability Redis cluster (e.g. AWS ElastiCache, Redis Sentinel, or KeyDB) in production environments.

### Neutral
- Adds network latency of approximately 1-2ms per storage round-trip, minimized through Redis pipeline batching.

## Alternatives Considered
- **In-Memory Cache with Background LRU Eviction Thread**: Rejected because it cannot solve the multi-pod state sharing problem in Kubernetes.
- **Relational Database (PostgreSQL/MySQL)**: Rejected due to unnecessary schema overhead, slower write throughput, and lack of native atomic key TTL expiration.
- **DynamoDB**: Viable on AWS, but Redis was selected for cloud-agnostic deployment flexibility and superior microsecond in-memory performance.

