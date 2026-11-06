# ADR 0001: Strict Zero-Trust Ingress Data Contracts via Pydantic v2

## Status
**ACCEPTED** (2026-11-05)

## Context
In an enterprise Zero-Trust security model, all incoming network requests originating from internal microservices, frontends, or partner APIs must be treated as untrusted. Traditional permissive JSON schemas ignore undeclared fields (`extra="ignore"`), allowing attackers to execute parameter smuggling, payload pollution, or inject metadata tags that bypass downstream compliance filters.

Furthermore, compliance tracing mandates that every transaction processed through the gateway be strictly auditable to an authenticated identity and conversation session.

## Decision
We mandate Pydantic v2 data contracts for all ingress payloads, implemented in [app/schemas.py](file:///c:/WWORKING_folder/ProjectFolders/zero-trust-llm-compliance-gateway/app/schemas.py) via `GatewayRequest`:

1. **Parameter Tampering Prevention (`extra="forbid"`)**: Any payload containing fields not explicitly declared in the data contract is immediately rejected with a `pydantic.ValidationError` (HTTP 422 at the network perimeter).
2. **Whitespace Stripping (`str_strip_whitespace=True`) & Mandatory Length (`min_length=1`)**: Prompts, session IDs, and user IDs cannot be blank, empty, or composed entirely of whitespace characters (`\t`, `\r`, `\n`).
3. **Mandatory Audit Identities**: `session_id` and `user_id` are required non-nullable fields on every incoming request.
4. **Extensibility via Defaults**: Optional parameters like `project_id` must provide safe, non-breaking defaults (`"default_project"`) to allow progressive adoption across multi-tenant tiers.

## Consequences

### Positive
- **Tamper-Proof Perimeter**: Prevents prototype pollution, parameter injection, and smuggling of unauthorized routing flags.
- **Fail-Closed by Design**: Malformed or incomplete inputs fail immediately at the edge before consuming cryptographic, tokenization, or LLM resources.
- **Zero Ambiguity**: Schemas generate strict OpenAPI / JSONSchema definitions for enterprise consumers.

### Negative / Tradeoffs
- Strict schemas reject benign extra fields sent by misconfigured client applications, requiring client teams to adhere strictly to published contracts.

### Neutral
- Schema validation introduces negligible CPU overhead (<0.5ms) leveraging Pydantic v2's compiled Rust core (`pydantic-core`).

## Alternatives Considered
- **Pydantic v1 / Standard Dataclasses**: Rejected due to slower validation performance and less expressive boundary configuration compared to Pydantic v2's Rust-backed core.
- **Permissive Ingress (`extra="ignore"`)**: Rejected because silently dropping extra parameters conceals client misconfigurations and opens parameter tampering vectors.

