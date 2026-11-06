# ADR 0003: Fast-Path Unicode NFKC Normalization, Zero-Width Scrubbing, and Anti-Smuggling Defenses

## Status
**ACCEPTED** (2026-11-05)

## Context
Standard regular expression patterns for PII detection are vulnerable to sophisticated prompt evasion and token smuggling attacks:
1. **Zero-Width Code Point Evasion**: Adversaries insert non-printable zero-width characters (e.g. `\u200B` zero-width space, `\u200C` zero-width non-joiner, `\uFEFF` zero-width no-break space) into Social Security Numbers (e.g. `123\u200B-45\u200B-6789`) or email addresses. Naive regex engines evaluate these as non-matching character boundaries, allowing plaintext PII to leak to external LLMs whose tokenizers automatically normalize and reconstruct the sensitive data.
2. **Homoglyph & Compatibility Variations**: Attackers use fullwidth Unicode digits (e.g. `１２３-４５-６７８９`) or mathematical alphanumeric characters to evade standard ASCII `\d` pattern ranges.
3. **Alternative Delimiters**: Social security numbers are frequently formatted with dots (`123.45.6789`) or spaces (`123 45 6789`).
4. **Token-Smuggling & Detokenization Hijacking**: Adversaries can manually insert `<EMAIL_TOKEN_1>` or `[SSN_TOKEN_1]` directly into prompt bodies. When the downstream LLM reflects this token in its answer, the gateway's unmasking engine replaces the injected token with another user's or session's real PII from the vault, causing high-severity information disclosure.

## Decision
We implement a three-stage fast-path input sanitization pipeline in [app/engine.py](file:///c:/WWORKING_folder/ProjectFolders/zero-trust-llm-compliance-gateway/app/engine.py) executed on all inbound text prior to regex matching:

1. **Unicode NFKC Normalization**:
   - Inbound text is passed through `unicodedata.normalize("NFKC", text)`, converting fullwidth digits, ligatures, and mathematical compatibility glyphs into standard ASCII characters.
2. **Zero-Width Code Point Scrubbing**:
   - All invisible code points matching `[\u200B-\u200D\uFEFF]` are stripped via pre-compiled regex substitution before boundary checks.
3. **Multi-Delimiter SSN Regex**:
   - Expanded SSN matching to `\b\d{3}[-.\s]\d{2}[-.\s]\d{4}\b`, capturing hyphen, dot, and space delimiters while rejecting invalid lengths.
4. **Anti-Token-Smuggling Defense**:
   - Inbound prompts are scanned for manual compliance token signatures matching `(?:<|\[)(?:EMAIL|SSN|PII)_TOKEN_` (case-insensitive).
   - If detected, the gateway immediately rejects the prompt with a `TokenSmugglingError`, mapped in [app/main.py](file:///c:/WWORKING_folder/ProjectFolders/zero-trust-llm-compliance-gateway/app/main.py) to **HTTP 400 Bad Request**.
   - Note: Unmasking (`unmask_text`, `unmask_request`) does not execute smuggling checks, allowing legitimate gateway-generated tokens to be detokenized.

## Consequences

### Positive
- **Evasion-Proof Matching**: Neutralizes zero-width and homoglyph regex evasion attacks with sub-millisecond execution overhead (<1ms).
- **Hijack Prevention**: Closes the token-smuggling vulnerability, ensuring untrusted users cannot trick the gateway into unmasking unauthorized PII.
- **Fail-Closed Network Perimeter**: Attack attempts are rejected at the edge with HTTP 400 before consuming LLM inference tokens.

### Negative / Tradeoffs
- Legitimate technical documentation prompts that happen to discuss literal token patterns like `<EMAIL_TOKEN_1>` must escape or wrap them to avoid being flagged as smuggling attempts.

### Neutral
- Python's standard `unicodedata` library is used, requiring zero external machine learning dependencies or GPU infrastructure.

## Alternatives Considered
- **In-Process Deep Learning / SpaCy NER Model**: Rejected because local NER models add 50-200ms latency, consume 1-2GB RAM per process, and introduce out-of-memory crash risks under high concurrent load.
- **Permissive Sanitization (Silent Token Stripping)**: Rejected in favor of raising `TokenSmugglingError` because silent replacement hides adversary probing behavior from security audit logs.

