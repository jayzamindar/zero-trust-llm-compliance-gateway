# GenAI Core Execution Runbook (`prompts/prompt.md`)
## Project: Zero-Trust GenAI Compliance Gateway

This runbook chronicles the exact Senior Staff Engineering prompts used to iteratively construct, secure, and test the distributed, fail-closed compliance gateway infrastructure.

---

## 📋 System Blueprint: Senior Staff Engineer Execution Mode

```text
Initialize Protocol B: Senior Staff Engineer Execution Mode.
Target Environment: VS Code Workspace running Python 3.12+ / FastAPI / Pydantic v2 / Redis.
Operational Principles:
1. Never output placeholders, code stubs, or `# TODO` items. Write complete, production-ready code.
2. Enforce strict type hinting and thorough docstrings for all signatures.
3. Prioritize asynchronous, non-blocking execution paths natively.
4. Enforce strict backwards compatibility through data contract validation.
```

---

## 🛠️ Prompt Execution Log

### Phase 1: Boundary Contracts & Data Defenses
**Prompt used to establish Pydantic V2 Ingress Constraints (`app/schemas.py`):**
```text
Act as a Principal Security Architect. Create the foundational data validation contracts for our Zero-Trust GenAI Compliance Gateway inside `app/schemas.py`. 
Enforce strict validation on inbound client requests using Pydantic v2. The request schema must strictly require a non-empty `prompt`, `session_id`, and `user_id`, and support an optional `project_id`. 
Crucially, apply configuration guardrails to reject any undeclared or unexpected fields (`extra="forbid"`) to prevent parameter pollution and token smuggling at the perimeter.
```

### Phase 2: Core Storage & Logic Decoupling
**Prompt used to establish the Asynchronous Database Abstraction (`app/storage.py` & `app/engine.py`):**
```text
Act as a Senior Infrastructure Engineer. Review our schemas and build a decoupled, asynchronous storage interface named `BaseTokenStorage` using Python's Abstract Base Classes (ABC). 
Implement two concrete providers: 
1) An `InMemoryTokenStorage` utilizing thread-safe reentrant locks (`threading.RLock`) supporting synchronous method execution for test runners alongside async compatibility wrappers.
2) A `RedisTokenStorage` using `redis.asyncio` with hash namespacing (`compliance:vault:{session_id}:*`) and sliding 3,600s TTL key expirations.
Update `ComplianceEngine` to leverage dependency injection for this storage tier, maintaining native async coroutines (`mask_async`, `unmask_async`) while preserving backward-compatible synchronous wrappers for pre-existing testing harnesses.
```

### Phase 3: Fast-Path Security & Normalization
**Prompt used to build Evasion defenses & Input Normalization Pipeline:**
```text
Act as a Principal Application Security Engineer. Layer an inbound string normalization and sanitization pipeline onto `ComplianceEngine` in `app/engine.py`. 
Before prompt text is passed to any regex scanning engines, the pipeline must:
1) Normalize incoming strings using `unicodedata.normalize('NFKC', text)` to flatten homoglyph bypass attempts.
2) Strip invisible zero-width characters (`\u200B` to `\u200D` and `\uFEFF`).
3) Expand regular expressions to catch Social Security Numbers formatted with dot, space, or hyphen delimiters.
4) Screen the prompt for token smuggling attempts by detecting raw, pre-existing compliance bracket structures, throwing an absolute `TokenSmugglingError` mapped to an `HTTP 400 Bad Request` in `app/main.py`.
```

### Phase 4: Financial Budgets & sliding Rate Limiters
**Prompt used to implement Token Quota Metrics (`tests/test_quota.py` & API integration):**
```text
Act as a FinOps Reliability Engineer. Integrate multi-tenant dynamic rate limiting and quota enforcement into the gateway. 
Extend our storage providers to track cumulative daily request counts and token spend calculations per `project_id` using atomic pipelines and a character-based token estimator heuristic (max(1, ceil(chars/4))). 
If a project tier exhausts its budget allocations, intercept the request before data masking occurs, throw a `QuotaExceededError`, and map it to an `HTTP 429 Too Many Requests` status code complete with standard `Retry-After` networking response headers.
```
