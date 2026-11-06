from datetime import datetime, timezone
import pytest
from fastapi import status
from fastapi.testclient import TestClient

from app.engine import ComplianceEngine, QuotaExceededError
from app.schemas import GatewayRequest
from app.storage import InMemoryTokenStorage, RedisTokenStorage
from tests.conftest import MockAsyncRedisClient


class TestTokenEstimation:
    """Tests fast-path prompt token estimation heuristics."""

    def test_token_estimation_accuracy(self):
        # Empty string
        assert ComplianceEngine.estimate_tokens("") == 0

        # Short prompt: 1 to 4 characters -> 1 token
        assert ComplianceEngine.estimate_tokens("A") == 1
        assert ComplianceEngine.estimate_tokens("Hi") == 1
        assert ComplianceEngine.estimate_tokens("Test") == 1

        # 8 characters -> 2 tokens
        assert ComplianceEngine.estimate_tokens("12345678") == 2

        # 40 characters -> 10 tokens
        sample = "a" * 40
        assert ComplianceEngine.estimate_tokens(sample) == 10


class TestQuotaEnforcementInMemory:
    """Tests request volume and token budget limits on InMemoryTokenStorage."""

    def test_daily_request_limit_enforcement(self, clean_engine: ComplianceEngine):
        clean_engine.set_project_budget("proj_capped_reqs", max_daily_requests=2)

        req1 = GatewayRequest(
            prompt="First prompt",
            session_id="s1",
            user_id="u1",
            project_id="proj_capped_reqs",
        )
        req2 = GatewayRequest(
            prompt="Second prompt",
            session_id="s1",
            user_id="u1",
            project_id="proj_capped_reqs",
        )
        req3 = GatewayRequest(
            prompt="Third prompt - should breach limit",
            session_id="s1",
            user_id="u1",
            project_id="proj_capped_reqs",
        )

        # First 2 succeed
        res1 = clean_engine.mask_request(req1)
        assert res1.prompt == "First prompt"
        res2 = clean_engine.mask_request(req2)
        assert res2.prompt == "Second prompt"

        # 3rd request breaches daily limit
        with pytest.raises(QuotaExceededError) as exc_info:
            clean_engine.mask_request(req3)
        assert "Daily request quota exceeded" in str(exc_info.value)
        assert "proj_capped_reqs" in str(exc_info.value)

    def test_daily_token_budget_enforcement(self, clean_engine: ComplianceEngine):
        # 16 characters = 4 tokens estimated
        # Set cap to 5 tokens
        clean_engine.set_project_budget("proj_capped_tokens", max_daily_tokens=5)

        # 12 chars = 3 tokens (under budget)
        req1 = GatewayRequest(
            prompt="Twelve chars",
            session_id="s1",
            user_id="u1",
            project_id="proj_capped_tokens",
        )
        res1 = clean_engine.mask_request(req1)
        assert res1.project_id == "proj_capped_tokens"

        # 16 chars = 4 tokens (3 + 4 = 7 > 5) -> breaches budget
        req2 = GatewayRequest(
            prompt="1234567890123456",
            session_id="s1",
            user_id="u1",
            project_id="proj_capped_tokens",
        )
        with pytest.raises(QuotaExceededError) as exc_info:
            clean_engine.mask_request(req2)
        assert "Daily token quota exceeded" in str(exc_info.value)

    def test_multi_project_quota_isolation(self, clean_engine: ComplianceEngine):
        """Exhausting Project A's quota must have zero impact on Project B."""
        clean_engine.set_project_budget("project_A", max_daily_requests=1)
        clean_engine.set_project_budget("project_B", max_daily_requests=10)

        req_a1 = GatewayRequest(
            prompt="Req 1 for A",
            session_id="s1",
            user_id="u1",
            project_id="project_A",
        )
        req_a2 = GatewayRequest(
            prompt="Req 2 for A",
            session_id="s1",
            user_id="u1",
            project_id="project_A",
        )
        req_b1 = GatewayRequest(
            prompt="Req 1 for B",
            session_id="s1",
            user_id="u2",
            project_id="project_B",
        )

        # Project A consumes its only request
        clean_engine.mask_request(req_a1)

        # Project A's 2nd request is blocked
        with pytest.raises(QuotaExceededError):
            clean_engine.mask_request(req_a2)

        # Project B continues to succeed normally
        res_b = clean_engine.mask_request(req_b1)
        assert res_b.project_id == "project_B"


class TestRouteQuotaEnforcement:
    """Tests network perimeter HTTP 429 response when quota is exceeded."""

    def test_route_quota_exceeded_returns_429(
        self, client: TestClient, clean_engine: ComplianceEngine
    ):
        clean_engine.set_project_budget("proj_api_rate_limited", max_daily_requests=1)

        payload = {
            "prompt": "Evaluate compliance for client.",
            "session_id": "sess_429_test",
            "user_id": "usr_429",
            "project_id": "proj_api_rate_limited",
        }

        # Request 1 succeeds
        res1 = client.post("/mask", json=payload)
        assert res1.status_code == status.HTTP_200_OK

        # Request 2 returns HTTP 429
        res2 = client.post("/mask", json=payload)
        assert res2.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert res2.headers.get("Retry-After") == "86400"

        data = res2.json()
        assert "quota exceeded" in data["detail"].lower()


class TestRedisQuotaStorage:
    """Tests distributed Redis daily sliding window bucket metrics and TTL."""

    @pytest.mark.asyncio
    async def test_redis_quota_storage_with_ttl(
        self, redis_storage: RedisTokenStorage, mock_redis_client: MockAsyncRedisClient
    ):
        project_id = "proj_redis_metrics"
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        quota_key = redis_storage._quota_key(project_id, today)

        # 1. Consume 10 tokens
        metric1 = await redis_storage.check_and_consume_quota(
            project_id=project_id,
            estimated_tokens=10,
            max_daily_requests=5,
            max_daily_tokens=100,
        )
        assert metric1["requests"] == 1
        assert metric1["tokens"] == 10
        assert mock_redis_client._ttls[quota_key] == 86400

        # 2. Consume another 25 tokens
        metric2 = await redis_storage.check_and_consume_quota(
            project_id=project_id,
            estimated_tokens=25,
            max_daily_requests=5,
            max_daily_tokens=100,
        )
        assert metric2["requests"] == 2
        assert metric2["tokens"] == 35

        # 3. Breach token limit
        with pytest.raises(QuotaExceededError) as exc_info:
            await redis_storage.check_and_consume_quota(
                project_id=project_id,
                estimated_tokens=70,  # 35 + 70 = 105 > 100
                max_daily_requests=5,
                max_daily_tokens=100,
            )
        assert "Daily token quota exceeded" in str(exc_info.value)

