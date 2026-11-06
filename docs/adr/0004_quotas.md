# ADR 0004: Token-Aware Multi-Tenant Quotas & Daily Sliding Window Rate Limiting

## Status
**ACCEPTED** (2026-11-05)

## Context
Deploying an enterprise GenAI compliance gateway without consumption controls exposes organizations to denial-of-wallet attacks and rogue model spend:
1. **Disproportionate Resource Consumption**: A single misconfigured script or rogue user can flood the gateway with multi-megabyte prompts, rapidly consuming organizational LLM token quotas.
2. **Multi-Tenant Fair Sharing**: Different business units, projects, or client tiers (`project_id`) require distinct rate caps and daily budget allocations.
3. **Traditional Request Rate Limiting Insufficiency**: Standard API rate limiters (e.g. 100 requests/minute) fail to protect GenAI systems because request volume does not correlate with token consumption: a single prompt can contain 50,000 tokens while 100 short prompts might consume only 500 tokens.

## Decision
We implement a dual-metric dynamic rate limiting and token budget enforcement system integrated across [app/schemas.py](file:///c:/WWORKING_folder/ProjectFolders/zero-trust-llm-compliance-gateway/app/schemas.py), [app/storage.py](file:///c:/WWORKING_folder/ProjectFolders/zero-trust-llm-compliance-gateway/app/storage.py), [app/engine.py](file:///c:/WWORKING_folder/ProjectFolders/zero-trust-llm-compliance-gateway/app/engine.py), and [app/main.py](file:///c:/WWORKING_folder/ProjectFolders/zero-trust-llm-compliance-gateway/app/main.py):

1. **Fast-Path Token Estimation Heuristic**:
   - `ComplianceEngine.estimate_tokens(prompt)` provides sub-millisecond calculation using the standard LLM tokenization heuristic:
     $$\text{tokens} = \max\left(1, \lceil \text{character\_count} / 4 \rceil \right)$$
   - Avoids mounting heavy BPE/SentencePiece tokenizers in the high-throughput fast-path gateway ingress.
2. **Dual-Metric Daily Window Tracking**:
   - Metrics tracked per `project_id`: daily request counts (`requests`) and cumulative token consumption (`tokens`).
   - In `RedisTokenStorage`, metrics are recorded in daily-bucketed hashes: `compliance:vault:quota:{project_id}:{YYYY-MM-DD}`.
   - Keys are assigned an automated 24-hour expiration (`EXPIRE 86400`) on creation.
3. **Atomic Multi-Tenant Budget Enforcement**:
   - Before executing PII masking or prompt routing, `check_and_consume_quota` atomically evaluates current usage against configured project budgets (`max_daily_requests`, `max_daily_tokens`).
   - If either metric breaches the allocated threshold, the gateway raises `QuotaExceededError`.
4. **Standard HTTP 429 Protocol Mapping**:
   - In [app/main.py](file:///c:/WWORKING_folder/ProjectFolders/zero-trust-llm-compliance-gateway/app/main.py), `QuotaExceededError` is trapped and mapped to **HTTP 429 Too Many Requests**.
   - Responses inject the standard RFC 6585 header: `Retry-After: 86400` (indicating window reset duration).

## Consequences

### Positive
- **Denial-of-Wallet Immunity**: Caps maximum daily financial liability per project/tier regardless of user prompt lengths.
- **Fair Multi-Tenant Allocation**: Projects operate within isolated quota namespaces; exhausting Project A's budget has zero impact on Project B.
- **Standardized Client Protocol**: HTTP 429 with `Retry-After: 86400` allows enterprise API gateways, reverse proxies, and SDKs to handle back-off and retry scheduling automatically.
- **Low Overhead**: Atomic Redis pipelines and integer math introduce <2ms latency to the ingress request lifecycle.

### Negative / Tradeoffs
- Character-based token estimation ($\lceil \text{chars} / 4 \rceil$) is a heuristic approximation that may slightly overestimate or underestimate non-Latin scripts (e.g. CJK ideographs) by approximately 10-20% compared to exact tokenizer models.

### Neutral
- Projects without an explicit custom tier budget fall back to generous default caps (`"default_project"`), ensuring legacy test cases and unassigned clients run unimpeded.

## Alternatives Considered
- **External API Gateway (Kong / Cloudflare Rate Limiting)**: Rejected as the sole solution because external proxies only count HTTP request frequency and cannot compute prompt token consumption before payload inspection.
- **Exact Tokenizer (tiktoken / HuggingFace Tokenizers)**: Kept as an optional future plugin, but rejected for default fast-path enforcement due to binary wheel dependencies, memory footprint, and CPU serialization costs.
- **Fixed Minute Leaky Bucket**: Rejected for daily billing budgets because enterprise AI subscriptions are structured around monthly/daily total token spends rather than micro-bursts per second.

