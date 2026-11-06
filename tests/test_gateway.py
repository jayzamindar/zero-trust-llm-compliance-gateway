import pytest
from fastapi import status
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.engine import ComplianceEngine, ComplianceEngineCrashError, TokenSmugglingError
from app.main import app, get_compliance_engine
from app.schemas import GatewayRequest


@pytest.fixture
def clean_engine() -> ComplianceEngine:
    """Fixture providing a fresh ComplianceEngine instance isolated from other tests."""
    return ComplianceEngine()


@pytest.fixture
def client(clean_engine: ComplianceEngine) -> TestClient:
    """
    Fixture providing a FastAPI TestClient with the dependency overridden
    to use the isolated clean_engine instance.
    """
    app.dependency_overrides[get_compliance_engine] = lambda: clean_engine
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def valid_request_payload() -> dict:
    """Standard valid payload for testing."""
    return {
        "prompt": "Hello compliance team. Review account for alice@example.com with SSN 123-45-6789.",
        "session_id": "sess_unit_test_001",
        "user_id": "usr_analyst_901",
    }


# ============================================================================
# 1. FAIL-CLOSED SECURITY RULES
# ============================================================================


class TestFailClosedRules:
    """
    Tests enforcing zero-trust boundary defenses and fail-closed behaviors:
    Any invalid contract, parameter tampering, or engine crash MUST fail closed.
    """

    # --- Boundary Contract Tests ---

    @pytest.mark.parametrize(
        "missing_field",
        ["prompt", "session_id", "user_id"],
    )
    def test_missing_required_fields_rejected(
        self, valid_request_payload: dict, missing_field: str
    ):
        """Zero-Trust: Missing required fields must immediately raise a validation error."""
        payload = dict(valid_request_payload)
        del payload[missing_field]

        with pytest.raises(ValidationError) as exc_info:
            GatewayRequest(**payload)

        errors = exc_info.value.errors()
        assert any(missing_field in err["loc"] for err in errors)

    def test_extra_fields_forbidden(self, valid_request_payload: dict):
        """Zero-Trust: Undeclared/tampered fields must be rejected (extra='forbid')."""
        payload = dict(valid_request_payload)
        payload["injected_param"] = "malicious_override"
        payload["role"] = "superadmin"

        with pytest.raises(ValidationError) as exc_info:
            GatewayRequest(**payload)

        errors = exc_info.value.errors()
        forbidden_fields = [
            err["loc"][0] for err in errors if err["type"] == "extra_forbidden"
        ]
        assert "injected_param" in forbidden_fields
        assert "role" in forbidden_fields

    @pytest.mark.parametrize(
        "field_name,blank_value",
        [
            ("prompt", ""),
            ("prompt", "   "),
            ("prompt", "\t\r\n"),
            ("session_id", ""),
            ("session_id", "   "),
            ("user_id", ""),
            ("user_id", "   "),
        ],
    )
    def test_whitespace_and_empty_fields_rejected(
        self, valid_request_payload: dict, field_name: str, blank_value: str
    ):
        """Zero-Trust: Whitespace-only or empty strings must be stripped and rejected."""
        payload = dict(valid_request_payload)
        payload[field_name] = blank_value

        with pytest.raises(ValidationError) as exc_info:
            GatewayRequest(**payload)

        errors = exc_info.value.errors()
        assert any(field_name in err["loc"] for err in errors)

    # --- Engine Crash & Resilience Tests ---

    def test_engine_health_check_crash_simulation(self, clean_engine: ComplianceEngine):
        """Engine health_check must fail closed by raising when simulate_crash is True."""
        with pytest.raises(ComplianceEngineCrashError):
            clean_engine.health_check(simulate_crash=True)

    def test_engine_simulated_crash_state(self, clean_engine: ComplianceEngine):
        """Engine crash toggle must persist until explicitly recovered."""
        clean_engine.simulate_crash(True)
        with pytest.raises(ComplianceEngineCrashError):
            clean_engine.health_check()

        # Recover engine and verify health restores
        clean_engine.simulate_crash(False)
        health = clean_engine.health_check()
        assert health["status"] == "healthy"

    def test_engine_health_check_non_throwing_mode(self, clean_engine: ComplianceEngine):
        """Non-throwing health check mode must report unhealthy status cleanly."""
        status_report = clean_engine.health_check(
            simulate_crash=True, raise_on_crash=False
        )
        assert status_report["status"] == "unhealthy"
        assert "error" in status_report

    def test_invalid_types_and_arguments_fail_closed(
        self, clean_engine: ComplianceEngine
    ):
        """Calling mask or unmask with raw text without session_id must fail immediately."""
        with pytest.raises(ValueError):
            clean_engine.mask("Text without session_id", session_id=None)

        with pytest.raises(ValueError):
            clean_engine.unmask("Text without session_id", session_id=None)

        with pytest.raises(TypeError):
            clean_engine.mask(12345, session_id="sess_1")  # type: ignore

    # --- Route-Level Proxy Fail-Closed Tests (FastAPI Boundary) ---

    def test_route_boundary_rejects_missing_fields(
        self, client: TestClient, valid_request_payload: dict
    ):
        """Network Boundary: Incomplete payload returns HTTP 422 Unprocessable Content."""
        payload = dict(valid_request_payload)
        del payload["prompt"]
        response = client.post("/mask", json=payload)
        assert response.status_code == 422

    def test_route_boundary_rejects_extra_fields(
        self, client: TestClient, valid_request_payload: dict
    ):
        """Network Boundary: Extra/tampered fields rejected with HTTP 422."""
        payload = dict(valid_request_payload)
        payload["tampered_key"] = "bypass"
        response = client.post("/mask", json=payload)
        assert response.status_code == 422

    def test_route_boundary_rejects_empty_prompt(
        self, client: TestClient, valid_request_payload: dict
    ):
        """Network Boundary: Whitespace prompt rejected with HTTP 422."""
        payload = dict(valid_request_payload)
        payload["prompt"] = "    "
        response = client.post("/mask", json=payload)
        assert response.status_code == 422

    def test_route_health_check_fails_closed_503(
        self, client: TestClient, clean_engine: ComplianceEngine
    ):
        """Network Boundary: Crashed engine causes /health to fail closed with HTTP 503."""
        clean_engine.simulate_crash(True)
        response = client.get("/health")
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

    def test_route_mask_fails_closed_503_on_engine_crash(
        self,
        client: TestClient,
        clean_engine: ComplianceEngine,
        valid_request_payload: dict,
    ):
        """Network Boundary: Crashed engine prevents /mask from processing, returning HTTP 503."""
        clean_engine.simulate_crash(True)
        response = client.post("/mask", json=valid_request_payload)
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        data = response.json()
        assert "unavailable" in data["detail"].lower()

    def test_route_unmask_fails_closed_503_on_engine_crash(
        self,
        client: TestClient,
        clean_engine: ComplianceEngine,
        valid_request_payload: dict,
    ):
        """Network Boundary: Crashed engine prevents /unmask from processing, returning HTTP 503."""
        clean_engine.simulate_crash(True)
        response = client.post("/unmask", json=valid_request_payload)
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


# ============================================================================
# 2. PII MASKING & EPHEMERAL TOKENIZATION RULES
# ============================================================================


class TestMaskingRules:
    """
    Tests enforcing deterministic, session-scoped PII masking and exact reverse unmasking.
    """

    def test_email_masking(self, clean_engine: ComplianceEngine):
        """Single and multiple distinct emails are masked with incremental tokens."""
        prompt = "Contact alice@example.com or reach out to bob.smith@sub.corp.io."
        masked = clean_engine.mask_text(prompt, session_id="s1")

        assert "alice@example.com" not in masked
        assert "bob.smith@sub.corp.io" not in masked
        assert "<EMAIL_TOKEN_1>" in masked
        assert "<EMAIL_TOKEN_2>" in masked

    def test_complex_email_masking(self, clean_engine: ComplianceEngine):
        """Plus addressing and complex RFC-compliant emails are properly masked."""
        prompt = "Alert dev+ops-monitor_10@test-company.co.uk immediately."
        masked = clean_engine.mask_text(prompt, session_id="s1")

        assert "dev+ops-monitor_10@test-company.co.uk" not in masked
        assert "<EMAIL_TOKEN_1>" in masked

    def test_ssn_masking(self, clean_engine: ComplianceEngine):
        """Formatted and space-separated SSNs are detected and masked."""
        prompt = "User 1 has SSN 123-45-6789 and User 2 has SSN 987 65 4321."
        masked = clean_engine.mask_text(prompt, session_id="s1")

        assert "123-45-6789" not in masked
        assert "987 65 4321" not in masked
        assert "<SSN_TOKEN_1>" in masked
        assert "<SSN_TOKEN_2>" in masked

    def test_combined_email_and_ssn_masking(self, clean_engine: ComplianceEngine):
        """Simultaneous email and SSN tokens are masked accurately."""
        prompt = "Report: john.doe@bank.com verified with SSN 456-78-1234."
        req = GatewayRequest(
            prompt=prompt, session_id="sess_comb", user_id="usr_audit"
        )
        masked_req = clean_engine.mask_request(req)

        assert "john.doe@bank.com" not in masked_req.prompt
        assert "456-78-1234" not in masked_req.prompt
        assert "<EMAIL_TOKEN_1>" in masked_req.prompt
        assert "<SSN_TOKEN_1>" in masked_req.prompt

    def test_referential_consistency_within_same_session(
        self, clean_engine: ComplianceEngine
    ):
        """
        Duplicate occurrences of the same PII entity within a session must reuse
        the identical token to maintain downstream LLM semantic integrity.
        """
        prompt = "Sender: support@desk.com. Please reply to support@desk.com or support@desk.com."
        masked = clean_engine.mask_text(prompt, session_id="s_repeat")

        assert "support@desk.com" not in masked
        assert masked.count("<EMAIL_TOKEN_1>") == 3
        assert "<EMAIL_TOKEN_2>" not in masked

    def test_cross_session_isolation(self, clean_engine: ComplianceEngine):
        """
        Zero-Trust Isolation: Tokens generated in session A must never resolve or leak
        in session B, even when using the same token identifier.
        """
        prompt_a = "Session A confidential email: secret_a@corp.com"
        prompt_b = "Session B confidential email: secret_b@corp.com"

        masked_a = clean_engine.mask_text(prompt_a, session_id="sess_A")
        masked_b = clean_engine.mask_text(prompt_b, session_id="sess_B")

        # Both get <EMAIL_TOKEN_1> within their isolated session namespaces
        assert "<EMAIL_TOKEN_1>" in masked_a
        assert "<EMAIL_TOKEN_1>" in masked_b

        # Unmasking session A's text using session B's vault must NOT reveal session A's email
        cross_unmasked = clean_engine.unmask_text(masked_a, session_id="sess_B")
        assert "secret_a@corp.com" not in cross_unmasked
        assert "secret_b@corp.com" in cross_unmasked

    def test_exact_roundtrip_unmasking(self, clean_engine: ComplianceEngine):
        """Masking followed by unmasking reproduces the original prompt byte-for-byte."""
        original_prompt = (
            "Verify customer john@fintech.io (SSN: 321-65-0987). "
            "Forward approval confirmation to compliance@fintech.io."
        )
        req = GatewayRequest(
            prompt=original_prompt, session_id="sess_roundtrip", user_id="u_rt"
        )

        masked_req = clean_engine.mask(req)
        assert isinstance(masked_req, GatewayRequest)
        assert original_prompt != masked_req.prompt

        unmasked_req = clean_engine.unmask(masked_req)
        assert isinstance(unmasked_req, GatewayRequest)
        assert unmasked_req.prompt == original_prompt

    def test_multi_digit_token_collision_safeguard(
        self, clean_engine: ComplianceEngine
    ):
        """
        When over 10 tokens exist in a session, unmasking must sort tokens by length
        to ensure <EMAIL_TOKEN_10> does not partially collide with <EMAIL_TOKEN_1>.
        """
        session_id = "sess_many_tokens"
        # Generate 12 unique emails in the session
        emails = [f"user_{i}@testcorp.org" for i in range(1, 13)]
        prompt = " ".join(emails)

        masked = clean_engine.mask_text(prompt, session_id=session_id)
        assert "<EMAIL_TOKEN_10>" in masked
        assert "<EMAIL_TOKEN_1>" in masked

        unmasked = clean_engine.unmask_text(masked, session_id=session_id)
        assert unmasked == prompt

    def test_unmask_nonexistent_session_returns_text_unchanged(
        self, clean_engine: ComplianceEngine
    ):
        """Unmasking in an unregistered session must safely return the text without error."""
        text = "Hello <EMAIL_TOKEN_1>"
        result = clean_engine.unmask_text(text, session_id="sess_unknown")
        assert result == text

    def test_pydantic_contract_preservation(
        self, clean_engine: ComplianceEngine, valid_request_payload: dict
    ):
        """Masked and unmasked requests must remain valid instances of GatewayRequest."""
        req = GatewayRequest(**valid_request_payload)
        masked = clean_engine.mask_request(req)
        assert isinstance(masked, GatewayRequest)
        assert masked.session_id == req.session_id
        assert masked.user_id == req.user_id

        unmasked = clean_engine.unmask_request(masked)
        assert isinstance(unmasked, GatewayRequest)
        assert unmasked.prompt == req.prompt

    # --- Route-Level Masking & Unmasking Integration Tests ---

    def test_route_mask_success(
        self, client: TestClient, valid_request_payload: dict
    ):
        """Network Boundary: POST /mask returns 200 with masked prompt and original IDs."""
        response = client.post("/mask", json=valid_request_payload)
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert "alice@example.com" not in data["prompt"]
        assert "123-45-6789" not in data["prompt"]
        assert "<EMAIL_TOKEN_1>" in data["prompt"]
        assert "<SSN_TOKEN_1>" in data["prompt"]
        assert data["session_id"] == valid_request_payload["session_id"]
        assert data["user_id"] == valid_request_payload["user_id"]

    def test_route_roundtrip_integration(
        self, client: TestClient, valid_request_payload: dict
    ):
        """Network Boundary: POST /mask followed by POST /unmask restores original prompt."""
        # 1. Mask prompt via HTTP API
        mask_response = client.post("/mask", json=valid_request_payload)
        assert mask_response.status_code == status.HTTP_200_OK
        masked_payload = mask_response.json()

        # 2. Unmask prompt via HTTP API
        unmask_response = client.post("/unmask", json=masked_payload)
        assert unmask_response.status_code == status.HTTP_200_OK
        unmasked_payload = unmask_response.json()

        assert unmasked_payload["prompt"] == valid_request_payload["prompt"]
        assert unmasked_payload["session_id"] == valid_request_payload["session_id"]
        assert unmasked_payload["user_id"] == valid_request_payload["user_id"]


# ============================================================================
# 3. FAST-PATH SECURITY & ANTI-SMUGGLING RULES
# ============================================================================


class TestFastPathSecurity:
    """
    Tests enforcing zero-trust Unicode normalization, zero-width stripping,
    multi-delimiter SSN detection, and strict token-smuggling defense.
    """

    def test_unicode_nfkc_normalization(self, clean_engine: ComplianceEngine):
        """Fullwidth digits (e.g. １２３-４５-６７８９) must be normalized via NFKC and masked."""
        prompt = "Review fullwidth SSN: １２３-４５-６７８９ for compliance."
        masked = clean_engine.mask_text(prompt, session_id="s_nfkc")
        assert "１２３-４５-６７８９" not in masked
        assert "<SSN_TOKEN_1>" in masked

    def test_zero_width_character_stripping(self, clean_engine: ComplianceEngine):
        """Zero-width characters inserted to evade regex must be scrubbed before matching."""
        # Zero-width spaces embedded in SSN and email
        prompt = "Suspicious SSN 123\u200B-45\u200C-6789\u200D and email alice\u200B@corp.com."
        masked = clean_engine.mask_text(prompt, session_id="s_zw")
        assert "123-45-6789" not in masked
        assert "alice@corp.com" not in masked
        assert "<SSN_TOKEN_1>" in masked
        assert "<EMAIL_TOKEN_1>" in masked

    @pytest.mark.parametrize(
        "ssn_variant",
        [
            "123-45-6789",  # standard dash
            "123.45.6789",  # dot separator
            "123 45 6789",  # space separator
        ],
    )
    def test_alternative_ssn_delimiters(
        self, clean_engine: ComplianceEngine, ssn_variant: str
    ):
        """Expanded regex matches hyphen, dot, and space delimiters."""
        prompt = f"Target SSN is {ssn_variant} in system."
        masked = clean_engine.mask_text(prompt, session_id="s_delim")
        assert ssn_variant not in masked
        assert "<SSN_TOKEN_1>" in masked

    def test_token_smuggling_rejection_angle_brackets(
        self, clean_engine: ComplianceEngine
    ):
        """User manually injecting <EMAIL_TOKEN_1> must be rejected with TokenSmugglingError."""
        forged_prompt = "User prompt trying to hijack <EMAIL_TOKEN_1> unmasking."
        with pytest.raises(TokenSmugglingError) as exc_info:
            clean_engine.mask_text(forged_prompt, session_id="s_smuggle")
        assert "Security Violation" in str(exc_info.value)

    def test_token_smuggling_rejection_square_brackets(
        self, clean_engine: ComplianceEngine
    ):
        """User injecting [SSN_TOKEN_1] or [EMAIL_TOKEN_ must be rejected with TokenSmugglingError."""
        forged_prompt = "Attacker payload with [SSN_TOKEN_1] injected manually."
        with pytest.raises(TokenSmugglingError):
            clean_engine.mask_text(forged_prompt, session_id="s_smuggle")

    def test_route_token_smuggling_fails_closed_400(
        self, client: TestClient, valid_request_payload: dict
    ):
        """Network boundary: POST /mask with smuggled tokens returns HTTP 400 Bad Request."""
        payload = dict(valid_request_payload)
        payload["prompt"] = "Attacker smuggling <EMAIL_TOKEN_1> to hijack response."
        response = client.post("/mask", json=payload)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert "Token smuggling detected" in data["detail"]

    def test_legitimate_unmask_not_blocked(self, clean_engine: ComplianceEngine):
        """Unmasking legitimately tokenized responses must proceed without triggering smuggling blocks."""
        prompt = "Customer email is john@safe.com."
        masked = clean_engine.mask_text(prompt, session_id="s_legit")
        assert "<EMAIL_TOKEN_1>" in masked

        # Unmasking does NOT trigger TokenSmugglingError
        unmasked = clean_engine.unmask_text(masked, session_id="s_legit")
        assert unmasked == prompt
